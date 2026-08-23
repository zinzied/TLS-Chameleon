"""
TLS-Chameleon: Raw TLS 1.3 ClientHello Emitter
==============================================

This module turns a *generated* fingerprint from ``gen_fingerprint`` into a
**byte-exact TLS 1.3 ClientHello** and completes a real handshake over a raw
socket. Unlike curl_cffi's ``impersonate`` (which hard-codes a fixed set of
ClientHellos), this emitter writes *our* cipher order, GREASE, extension
layout, key_share and ALPN -- so the server observes exactly the JA3/JA4 we
computed. This is what makes the generative engine real on the wire.

Scope (intentional, minimal):
  * TLS 1.3 only (servers falling back to 1.2 -> we abort, by design)
  * Key exchange: X25519 (group 29)
  * AEAD: AES-128/256-GCM, ChaCha20-Poly1305 (whatever the server picks)
  * ALPN is negotiated; only HTTP/1.1 is spoken (h2 framing is out of scope)
  * Certificate verification is SKIPPED (this is a fingerprint probe; add
    verification before trust-sensitive use)

The emitted ClientHello is built directly from ``profile['ciphers']`` and
``profile['extensions']`` (decimal IDs, GREASE included) so the wire JA3 is
identical to the one the engine computed.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import socket
import struct
from typing import Dict, Any, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TLS_VERSION_13 = 0x0304
RECORD_HEADER = 5
CT_HANDSHAKE = 0x16
CT_APPLICATION_DATA = 0x17

HT_CLIENT_HELLO = 0x01
HT_SERVER_HELLO = 0x02
HT_ENCRYPTED_EXTENSIONS = 0x08
HT_CERTIFICATE = 0x0B
HT_CERTIFICATE_VERIFY = 0x0F
HT_FINISHED = 0x14

EXT_SERVER_NAME = 0
EXT_EC_POINT_FORMATS = 11
EXT_SIGNATURE_ALGORITHMS = 13
EXT_ALPN = 16
EXT_SUPPORTED_VERSIONS = 43
EXT_KEY_SHARE = 51
EXT_PSK_KEY_EXCHANGE_MODES = 45

GROUP_X25519 = 29

# cipher_id -> (key_len, iv_len, kind, hashmod)
AEAD_PARAMS = {
    4865: (16, 12, "aes128", "sha256"),
    4866: (32, 12, "aes256", "sha384"),
    4867: (32, 12, "chacha20", "sha256"),
}


# ---------------------------------------------------------------------------
# HKDF (TLS 1.3)
# ---------------------------------------------------------------------------

def _hkdf_extract(salt: bytes, ikm: bytes, hf=hashlib.sha256) -> bytes:
    return hmac.new(salt, ikm, hf).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int, hf=hashlib.sha256) -> bytes:
    t = b""
    okm = b""
    i = 0
    while len(okm) < length:
        i += 1
        t = hmac.new(prk, t + info + bytes([i]), hf).digest()
        okm += t
    return okm[:length]


def _expand_label(secret: bytes, label: str, context: bytes, length: int, hf=hashlib.sha256) -> bytes:
    full = b"tls13 " + label.encode()
    hkdflabel = (
        struct.pack("!H", length)
        + bytes([len(full)]) + full
        + bytes([len(context)]) + context
    )
    return _hkdf_expand(secret, hkdflabel, length, hf)


def _derive_secret(secret: bytes, label: str, transcript_hash: bytes, hlen: int = 32,
                   hf=hashlib.sha256) -> bytes:
    return _expand_label(secret, label, transcript_hash, hlen, hf)


def _th(data: bytes, hf=hashlib.sha256) -> bytes:
    return hf(data).digest()


# ---------------------------------------------------------------------------
# AEAD
# ---------------------------------------------------------------------------

def _aesgcm(key: bytes, iv: bytes, nonce: bytes, aad: bytes, data: bytes, encrypt: bool) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    # `nonce` already = iv XOR seq (see _nonce); use it directly
    g = AESGCM(key)
    return g.encrypt(nonce, data, aad) if encrypt else g.decrypt(nonce, data, aad)


def _chacha(key: bytes, nonce12: bytes, aad: bytes, data: bytes, encrypt: bool) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    c = ChaCha20Poly1305(key)
    return c.encrypt(nonce12, data, aad) if encrypt else c.decrypt(nonce12, data, aad)


# ---------------------------------------------------------------------------
# Record layer
# ---------------------------------------------------------------------------

def _record(content_type: int, body: bytes) -> bytes:
    return struct.pack("!BHH", content_type, 0x0303, len(body)) + body


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed prematurely")
        buf += chunk
    return buf


def _read_record(sock: socket.socket) -> Tuple[int, bytes]:
    header = _recv_exact(sock, RECORD_HEADER)
    ctype, version, length = struct.unpack("!BHH", header)
    return ctype, _recv_exact(sock, length)


# ---------------------------------------------------------------------------
# ClientHello construction (byte-exact from the generated profile)
# ---------------------------------------------------------------------------

def _ext_server_name(host: str) -> bytes:
    name = host.encode()
    # ServerNameList(2-byte len) -> ServerName(name_type=0) + host_name(2-byte len)
    host_field = bytes([0]) + struct.pack("!H", len(name)) + name
    return struct.pack("!H", len(host_field)) + host_field


def _ext_supported_versions() -> bytes:
    # SupportedVersions: versions vector uses a 1-byte length prefix
    return bytes([2]) + struct.pack("!H", TLS_VERSION_13)


def _ext_key_share(pubkey: bytes) -> bytes:
    entry = struct.pack("!H", GROUP_X25519) + struct.pack("!H", len(pubkey)) + pubkey
    return struct.pack("!H", len(entry)) + entry


def _ext_alpn(protocols: List[str]) -> bytes:
    inner = b"".join(bytes([len(pb)]) + pb for pb in (p.encode() for p in protocols))
    return struct.pack("!H", len(inner)) + inner


def _ext_sig_algs(ids: List[int]) -> bytes:
    body = b"".join(struct.pack("!H", i) for i in ids)
    return struct.pack("!H", len(body)) + body


def _ext_ec_point_formats() -> bytes:
    return bytes([1, 0])


def _ext_supported_groups(groups: List[int]) -> bytes:
    body = b"".join(struct.pack("!H", g) for g in groups)
    return struct.pack("!H", len(body)) + body


def _ext_psk_modes() -> bytes:
    # list length 1, mode 0x01 (psk_ke)
    return bytes([1, 0x01])


def _build_extension(ext_id: int, profile: Dict[str, Any], host: str, pubkey: bytes) -> Optional[bytes]:
    """Return extension BODY for known IDs; None => empty body (GREASE/unknown)."""
    if ext_id == EXT_SERVER_NAME:
        return _ext_server_name(host)
    if ext_id == EXT_SUPPORTED_VERSIONS:
        return _ext_supported_versions()
    if ext_id == EXT_KEY_SHARE:
        return _ext_key_share(pubkey)
    if ext_id == EXT_ALPN:
        return _ext_alpn(profile.get("alpn", ["http/1.1"]))
    if ext_id == EXT_SIGNATURE_ALGORITHMS:
        return _ext_sig_algs(profile.get("signature_algorithms", [1027, 1283, 1539, 1025, 1281, 1537]))
    if ext_id == EXT_EC_POINT_FORMATS:
        return _ext_ec_point_formats()
    if ext_id == 10:  # supported_groups
        return _ext_supported_groups(profile.get("supported_groups", [GROUP_X25519]))
    if ext_id == EXT_PSK_KEY_EXCHANGE_MODES:
        return _ext_psk_modes()
    if ext_id == 65281:  # renegotiation_info (RFC 5746) - empty RCI list
        return b"\x00"
    if ext_id == 5:  # status_request (OCSP) - type=1, empty lists
        return struct.pack("!B", 1) + b"\x00\x00" + b"\x00\x00"
    return None


def encode_client_hello(profile: Dict[str, Any], host: str, pubkey: bytes,
                        random_bytes: bytes) -> bytes:
    """Build the raw ClientHello *message* (no record header) from a profile.

    Cipher and extension order are taken verbatim from the profile so the
    emitted JA3 matches the computed one exactly (GREASE included).
    """
    cipher_ids = profile["ciphers"]  # numeric, may include GREASE ints
    ciphers = b"".join(struct.pack("!H", c & 0xFFFF) for c in cipher_ids)

    ext_sections = b""
    for ext_id in profile["extensions"]:
        body = _build_extension(ext_id, profile, host, pubkey)
        if body is None:
            body = b""  # GREASE / unknown -> empty body (server ignores)
        ext_sections += struct.pack("!HH", ext_id & 0xFFFF, len(body)) + body
    extensions = struct.pack("!H", len(ext_sections)) + ext_sections

    body = b""
    body += struct.pack("!H", 0x0303)             # legacy_version
    body += random_bytes                         # 32-byte random
    body += bytes([0])                           # legacy_session_id (empty)
    body += struct.pack("!H", len(ciphers)) + ciphers
    body += bytes([0x01, 0x00])                  # legacy compression (null)
    body += extensions

    msg = struct.pack("!B", HT_CLIENT_HELLO) + struct.pack("!I", len(body))[1:] + body
    return msg


# ---------------------------------------------------------------------------
# Minimal TLS 1.3 client
# ---------------------------------------------------------------------------

class TLS13Client:
    def __init__(self, profile: Dict[str, Any], host: str, port: int = 443,
                 timeout: float = 20.0, alpn: Optional[List[str]] = None):
        self.profile = profile
        self.host = host
        self.port = port
        self.timeout = timeout
        self.alpn = alpn or profile.get("alpn", ["http/1.1"])
        self.sock: Optional[socket.socket] = None
        self.cipher_id: Optional[int] = None
        self.negotiated_alpn: Optional[str] = None
        self._client_priv: Optional[X25519PrivateKey] = None
        self._server_pubkey: bytes = b""
        self._transcript = b""          # handshake messages with headers
        self._ch_sh = b""               # transcript up to and including ServerHello
        self._hs_buf = b""              # decrypted inbound handshake bytes
        self._client_seq = 0
        self._server_seq = 0
        self._c_hs_key = self._c_hs_iv = None
        self._s_hs_key = self._s_hs_iv = None
        self._c_ap_key = self._c_ap_iv = None
        self._s_ap_key = self._s_ap_iv = None
        self._server_finished_body: bytes = b""
        self._hf = hashlib.sha256
        self._hlen = 32
        self._ae = "aes128"

    # ---- public API --------------------------------------------------------
    def connect(self) -> None:
        if self.sock is None:
            self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._handshake()

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def request(self, method: str, path: str, headers: Optional[Dict[str, str]] = None,
                body: bytes = b"") -> bytes:
        if self.sock is None:
            self.connect()
        hdrs = {
            "Host": self.host,
            "User-Agent": self.profile.get("user_agent", "TLS-Chameleon/2.0"),
            "Accept": "*/*",
            "Connection": "close",
        }
        if headers:
            hdrs.update(headers)
        req = f"{method} {path} HTTP/1.1\r\n"
        req += "\r\n".join(f"{k}: {v}" for k, v in hdrs.items())
        if body:
            req += f"\r\nContent-Length: {len(body)}\r\n\r\n"
            req = (req.encode() + body)
        else:
            req += "\r\n\r\n"
            req = req.encode()
        self._send_app(req)
        return self._read_http()

    # ---- handshake ----------------------------------------------------------
    def _add(self, msg: bytes) -> None:
        self._transcript += msg

    def _handshake(self) -> None:
        self._client_priv = X25519PrivateKey.generate()
        pubkey = self._client_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        client_random = os.urandom(32)

        ch = encode_client_hello(self.profile, self.host, pubkey, client_random)
        self.sock.sendall(_record(CT_HANDSHAKE, ch))
        self._add(ch)

        # --- ServerHello (plaintext) ---
        ctype, sh_record = _read_record(self.sock)
        if ctype != CT_HANDSHAKE or sh_record[0] != HT_SERVER_HELLO:
            raise RuntimeError("expected ServerHello")
        sh_len = int.from_bytes(sh_record[1:4], "big")
        sh_full = sh_record[:4 + sh_len]
        self._add(sh_full)
        self._ch_sh = self._transcript  # freeze CH+SH before any encrypted records
        self._sh_raw = sh_record  # keep for independent re-parse
        self._parse_server_hello(sh_record[4:4 + sh_len])

        self._derive_handshake_keys()

        # --- encrypted handshake: EE, Certificate, CertVerify, Finished ---
        self._read_server_finished()

        # verify server Finished (over transcript EXCLUDING server Finished)
        # RFC 8446 sec 4.4.4: verify_data = HMAC(finished_key, Transcript-Hash(...))
        #   finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", Hash.length)
        th1 = _th(self._transcript[: -len(self._server_finished_full())], self._hf)
        s_hs = _derive_secret(self._handshake_secret(), "s hs traffic",
                              _th(self._ch_sh_transcript(), self._hf), self._hlen, self._hf)
        finished_key = _expand_label(s_hs, "finished", b"", self._hlen, self._hf)
        verify = hmac.new(finished_key, th1, self._hf).digest()
        if not hmac.compare_digest(self._server_finished_body, verify):
            raise RuntimeError("server Finished verification failed")

        # send client Finished (over transcript INCLUDING server Finished)
        self._send_client_finished()

        # application keys (full transcript incl. client Finished)
        self._derive_application_keys()

    def _parse_server_hello(self, body: bytes) -> None:
        off = 2  # skip legacy_version
        off += 32  # server random
        sid_len = body[off]; off += 1
        off += sid_len
        self.cipher_id = struct.unpack("!H", body[off:off + 2])[0]; off += 2
        assert body[off] == 0; off += 1  # compression
        ext_total = struct.unpack("!H", body[off:off + 2])[0]; off += 2
        end = off + ext_total
        while off < end:
            eid = struct.unpack("!H", body[off:off + 2])[0]; off += 2
            elen = struct.unpack("!H", body[off:off + 2])[0]; off += 2
            edata = body[off:off + elen]; off += elen
            if eid == EXT_SUPPORTED_VERSIONS:
                if int.from_bytes(edata, "big") != TLS_VERSION_13:
                    raise RuntimeError("server did not select TLS 1.3")
            elif eid == EXT_KEY_SHARE:
                g = struct.unpack("!H", edata[0:2])[0]
                klen = struct.unpack("!H", edata[2:4])[0]
                self._server_pubkey = edata[4:4 + klen]
                if g != GROUP_X25519:
                    raise RuntimeError(f"unsupported server group {g}")
            elif eid == EXT_ALPN:
                plen = edata[1]
                self.negotiated_alpn = edata[2:2 + plen].decode()
        # select handshake hash from the negotiated cipher suite
        if self.cipher_id is not None:
            _, _, _, halg = AEAD_PARAMS[self.cipher_id]
            self._hf = getattr(hashlib, halg)
            self._hlen = self._hf().digest_size
            self._ae = AEAD_PARAMS[self.cipher_id][2]

    def _ch_sh_transcript(self) -> bytes:
        # transcript up to and including ServerHello (frozen before encrypted records)
        return self._ch_sh

    def _server_finished_full(self) -> bytes:
        return getattr(self, "_sf_full", b"")

    def _handshake_secret(self) -> bytes:
        zeros = bytes(self._hlen)
        # RFC 8446 sec 7.1: the "0" PSK is a Hash.length-length string of zeros.
        early = _hkdf_extract(zeros, zeros, self._hf)
        derived = _expand_label(early, "derived", _th(b"", self._hf), self._hlen, self._hf)
        shared = self._client_priv.exchange(X25519PublicKey.from_public_bytes(self._server_pubkey))
        return _hkdf_extract(derived, shared, self._hf)

    def _derive_handshake_keys(self) -> None:
        hs = self._handshake_secret()
        th = _th(self._ch_sh_transcript(), self._hf)
        c_hs = _derive_secret(hs, "c hs traffic", th, self._hlen, self._hf)
        s_hs = _derive_secret(hs, "s hs traffic", th, self._hlen, self._hf)
        kl, ivl, _, _ = AEAD_PARAMS[self.cipher_id]
        self._c_hs_key = _expand_label(c_hs, "key", b"", kl, self._hf)
        self._c_hs_iv = _expand_label(c_hs, "iv", b"", ivl, self._hf)
        self._s_hs_key = _expand_label(s_hs, "key", b"", kl, self._hf)
        self._s_hs_iv = _expand_label(s_hs, "iv", b"", ivl, self._hf)

    def _read_server_finished(self) -> None:
        while True:
            ctype, body = _read_record(self.sock)
            if ctype != CT_APPLICATION_DATA:
                continue  # ignore CCS (0x14) etc.
            try:
                plain, ctype_inner = self._decrypt(body, self._s_hs_key,
                                                   self._s_hs_iv, self._server_seq, is_hs=True)
                self._server_seq += 1
            except Exception:
                raise RuntimeError("server handshake decryption failed")

            self._hs_buf += plain
            while len(self._hs_buf) >= 4:
                mtype = self._hs_buf[0]
                mlen = int.from_bytes(self._hs_buf[1:4], "big")
                if len(self._hs_buf) < 4 + mlen:
                    break
                msg = self._hs_buf[:4 + mlen]
                self._add(msg)
                self._hs_buf = self._hs_buf[4 + mlen:]
                # skip RFC 8446 zero-padding that follows this record's message;
                # a handshake message type is never 0x00, so leading zeros here
                # can only be padding.
                while self._hs_buf and self._hs_buf[0] == 0:
                    self._hs_buf = self._hs_buf[1:]
                if mtype == HT_FINISHED:
                    self._sf_full = msg
                    self._server_finished_body = msg[4:]
                    return

    def _send_client_finished(self) -> None:
        th = _th(self._transcript, self._hf)  # includes server Finished -> HMAC input
        # RFC 8446 sec 4.4.4: derive with CH+SH transcript, then finished_key for HMAC
        c_hs = _derive_secret(self._handshake_secret(), "c hs traffic",
                              _th(self._ch_sh_transcript(), self._hf), self._hlen, self._hf)
        finished_key = _expand_label(c_hs, "finished", b"", self._hlen, self._hf)
        verify = hmac.new(finished_key, th, self._hf).digest()
        finished = struct.pack("!B", HT_FINISHED) + struct.pack("!I", len(verify))[1:] + verify
        self._add(finished)
        self._send_hs(finished)

    def _derive_application_keys(self) -> None:
        hs = self._handshake_secret()
        zeros = bytes(self._hlen)
        # RFC 8446 sec 7.1: master_secret = HKDF-Extract(Derive-Secret(hs,"derived",""), 0)
        derived = _expand_label(hs, "derived", _th(b"", self._hf), self._hlen, self._hf)
        master = _hkdf_extract(derived, zeros, self._hf)
        th = _th(self._transcript, self._hf)
        c_ap = _derive_secret(master, "c ap traffic", th, self._hlen, self._hf)
        s_ap = _derive_secret(master, "s ap traffic", th, self._hlen, self._hf)
        kl, ivl, _, _ = AEAD_PARAMS[self.cipher_id]
        self._c_ap_key = _expand_label(c_ap, "key", b"", kl, self._hf)
        self._c_ap_iv = _expand_label(c_ap, "iv", b"", ivl, self._hf)
        self._s_ap_key = _expand_label(s_ap, "key", b"", kl, self._hf)
        self._s_ap_iv = _expand_label(s_ap, "iv", b"", ivl, self._hf)

    # ---- AEAD helpers -------------------------------------------------------
    def _nonce(self, iv: bytes, seq: int) -> bytes:
        return bytes(a ^ b for a, b in zip(iv, b"\x00" * 4 + seq.to_bytes(8, "big")))

    def _decrypt(self, body: bytes, key: bytes, iv: bytes, seq: int, is_hs: bool):
        kl, ivl, kind, _ = AEAD_PARAMS[self.cipher_id]
        aad = struct.pack("!BHH", CT_APPLICATION_DATA, 0x0303, len(body))
        nonce = self._nonce(iv, seq)
        if kind == "chacha20":
            pt = _chacha(key, nonce, aad, body, encrypt=False)
        else:
            pt = _aesgcm(key, iv, nonce, aad, body, encrypt=False)
        # RFC 8446 5.2: TLSInnerPlaintext = content + zero-padding + content_type.
        # The final byte is the inner content type. We must NOT blindly strip trailing
        # zeros, because the inner content (a handshake message) may itself end in 0x00.
        # Handshake message framing (the 3-byte length field) delimits the real content;
        # only the single trailing content-type byte is removed here.
        ctype_inner = pt[-1]
        return pt[:-1], ctype_inner

    def _send_hs(self, msg: bytes) -> None:
        self._send_protected(msg, self._c_hs_key, self._c_hs_iv, CT_HANDSHAKE)

    def _send_app(self, data: bytes) -> None:
        self._send_protected(data, self._c_ap_key, self._c_ap_iv, CT_APPLICATION_DATA)

    def _send_protected(self, data: bytes, key: bytes, iv: bytes, inner_type: int) -> None:
        kl, ivl, kind, _ = AEAD_PARAMS[self.cipher_id]
        inner = data + bytes([inner_type])
        nonce = self._nonce(iv, self._client_seq)
        aad = struct.pack("!BHH", CT_APPLICATION_DATA, 0x0303, len(inner) + 16)
        if kind == "chacha20":
            ct = _chacha(key, nonce, aad, inner, encrypt=True)
        else:
            ct = _aesgcm(key, iv, nonce, aad, inner, encrypt=True)
        self.sock.sendall(struct.pack("!BHH", CT_APPLICATION_DATA, 0x0303, len(ct)) + ct)
        self._client_seq += 1

    def _read_http(self) -> bytes:
        out = b""
        self.sock.settimeout(self.timeout)
        try:
            while True:
                ctype, body = _read_record(self.sock)
                if ctype != CT_APPLICATION_DATA:
                    continue
                plain, inner = self._decrypt(body, self._s_ap_key, self._s_ap_iv,
                                             self._server_seq, is_hs=False)
                self._server_seq += 1
                if inner == CT_APPLICATION_DATA:
                    out += plain
                # ignore NewSessionTicket / other inner types
        except ConnectionError:
            pass
        return out
