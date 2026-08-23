"""``doctor``: explain WHY a connection behaves the way it does.

A diagnostic system, NOT a bypass tool. Every check reports what was
observed, what it means, and -- when something looks wrong -- a concrete
recommendation. Checks that cannot be performed are marked ``skip``,
never guessed.
"""

from dataclasses import dataclass, field
from time import perf_counter
from typing import Any, Dict, List, Optional

__all__ = ["CheckResult", "DoctorReport", "doctor"]

STATUS_OK = "ok"
STATUS_WARN = "warn"
STATUS_FAIL = "fail"
STATUS_SKIP = "skip"

_SYMBOLS = {STATUS_OK: "✓", STATUS_WARN: "⚠", STATUS_FAIL: "✗", STATUS_SKIP: "-"}
# ASCII fallback for terminals that cannot render the symbols above.
_SYMBOLS_ASCII = {STATUS_OK: "OK", STATUS_WARN: "!!", STATUS_FAIL: "X", STATUS_SKIP: "--"}


def _safe_symbol(status: str) -> str:
    """Unicode symbol when the terminal supports it, ASCII otherwise."""
    import sys

    symbol = _SYMBOLS.get(status, "?")
    try:
        symbol.encode(sys.stdout.encoding or "ascii")
    except (LookupError, UnicodeEncodeError):
        return _SYMBOLS_ASCII.get(status, "?")
    return symbol


@dataclass
class CheckResult:
    """Outcome of one doctor check."""

    name: str
    status: str  # ok | warn | fail | skip
    detail: str = ""
    recommendation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "recommendation": self.recommendation,
        }


@dataclass
class DoctorReport:
    """Full diagnostic report for one target."""

    url: str
    checks: List[CheckResult] = field(default_factory=list)
    verdict: str = STATUS_OK

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": "tls-chameleon.doctor/1",
            "url": self.url,
            "verdict": self.verdict,
            "checks": [c.to_dict() for c in self.checks],
        }

    def to_text(self) -> str:
        lines = [f"TLS-Chameleon Doctor - {self.url}", ""]
        for check in self.checks:
            symbol = _safe_symbol(check.status)
            lines.append(f"[{symbol:>2}] {check.name}: {check.detail}")
            if check.recommendation:
                lines.append(f"       -> {check.recommendation}")
        lines.append("")
        lines.append(f"Verdict: {self.verdict.upper()}")
        return "\n".join(lines)


def doctor(
    url: str,
    client: Optional[Any] = None,
    *,
    echo_endpoint: Optional[str] = None,
    timeout: float = 15.0,
) -> DoctorReport:
    """Run all diagnostics against ``url``.

    Args:
        url: Target to probe with a single GET.
        client: Existing ``TLSChameleon``; a temporary default one is used
            (and closed) otherwise.
        echo_endpoint: Optional TLS-echo URL enabling observed-vs-profile
            fingerprint comparison (one extra request through same session).
        timeout: Per-request timeout in seconds.
    """
    close_after = False
    if client is None:
        from ..client import TLSChameleon

        client = TLSChameleon(timeout=timeout)
        close_after = True

    report = DoctorReport(url=url)
    try:
        report.checks.extend(_connection_checks(url, client, timeout))
        report.checks.append(_backend_check(client))
        report.checks.extend(_profile_checks(client))
        report.checks.append(_security_check(client))
        if echo_endpoint:
            report.checks.extend(
                _fingerprint_checks(client, echo_endpoint, timeout)
            )
    finally:
        if close_after:
            try:
                client.close()
            except Exception:  # pragma: no cover - best effort
                pass

    statuses = {check.status for check in report.checks}
    if STATUS_FAIL in statuses:
        report.verdict = STATUS_FAIL
    elif STATUS_WARN in statuses:
        report.verdict = STATUS_WARN
    else:
        report.verdict = STATUS_OK
    return report


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _connection_checks(url: str, client: Any, timeout: float) -> List[CheckResult]:
    from .trace import collect_trace

    checks: List[CheckResult] = []
    started = perf_counter()
    trace = None
    try:
        response = client.session.request("GET", url, timeout=timeout)
        total_ms = (perf_counter() - started) * 1000.0
        trace = collect_trace(
            "GET", url, response,
            backend=getattr(client, "engine", None),
            profile=getattr(client, "profile_name", None),
            total_ms=total_ms,
        )
    except Exception as exc:
        checks.append(
            CheckResult(
                "Connection",
                STATUS_FAIL,
                f"request failed ({type(exc).__name__}: {exc})",
                "Check network reachability / proxy configuration.",
            )
        )
        return checks

    status = trace.status_code
    if isinstance(status, int) and status < 400:
        checks.append(
            CheckResult(
                "Connection",
                STATUS_OK,
                f"{trace.protocol or 'protocol unknown'} response "
                f"{status} in {trace.timing_ms.get('total', 0):.0f}ms",
            )
        )
    elif isinstance(status, int):
        checks.append(
            CheckResult(
                "Connection",
                STATUS_WARN,
                f"server answered HTTP {status}",
                None if status < 500 else "Server-side error; possibly rate limiting.",
            )
        )

    # TLS observability is backend-dependent: report honestly.
    checks.append(
        CheckResult(
            "TLS visibility",
            STATUS_SKIP,
            "TLS version/ALPN not observable on arbitrary URLs via this backend; "
            "use echo_endpoint=True for observed fingerprint comparison",
        )
    )
    del trace
    return checks


def _backend_check(client: Any) -> CheckResult:
    capabilities = getattr(client, "capabilities", None)
    name = getattr(client, "engine", "unknown")
    spoofing = bool(getattr(capabilities, "tls_fingerprint_spoofing", False))
    profile_data = getattr(client, "_current_profile_data", None) or {}
    wants_impersonation = bool(profile_data.get("impersonate"))

    if wants_impersonation and not spoofing:
        return CheckResult(
            "Backend",
            STATUS_WARN,
            f"active backend '{name}' cannot perform TLS-level impersonation "
            f"(profile requests '{profile_data.get('impersonate')}')",
            "Install the curl extra: pip install tls-chameleon[curl]",
        )
    detail = (
        f"backend '{name}' performs real TLS impersonation"
        if spoofing
        else f"backend '{name}' uses standard TLS (no JA3 spoofing)"
    )
    return CheckResult("Backend", STATUS_OK, detail)


def _profile_checks(client: Any) -> List[CheckResult]:
    checks: List[CheckResult] = []
    profile_name = getattr(client, "profile_name", None)
    info = client.get_fingerprint_info()

    if not profile_name or not info.get("user_agent"):
        checks.append(
            CheckResult(
                "Profile", STATUS_FAIL, "no usable profile loaded",
                "Pass profile=<name>; see list_available_profiles().",
            )
        )
        return checks

    checks.append(
        CheckResult("Profile", STATUS_OK, f"profile '{profile_name}' loaded")
    )

    from ..fingerprint.adapter import fingerprint_from_legacy
    from ..fingerprint.validator import validate_fingerprint
    from ..fingerprint.headers import check_header_consistency

    fingerprint = fingerprint_from_legacy(dict(info), name=str(profile_name))
    issues = validate_fingerprint(fingerprint)
    errors = [i for i in issues if i.severity == "error"]
    warnings = [i for i in issues if i.severity == "warning"]
    if errors:
        checks.append(
            CheckResult(
                "Profile validity", STATUS_FAIL,
                "; ".join(i.message for i in errors),
                "Fix the reported profile problems before relying on it.",
            )
        )
    elif warnings:
        checks.append(
            CheckResult(
                "Profile validity", STATUS_WARN,
                "; ".join(i.message for i in warnings),
            )
        )
    else:
        checks.append(CheckResult("Profile validity", STATUS_OK, "no issues found"))

    # Phase 4: header consistency (Chrome UA + Firefox hints, etc.)
    header_issues = check_header_consistency(client._current_profile_data or {})
    header_errors = [i for i in header_issues if i.severity == "error"]
    header_warnings = [i for i in header_issues if i.severity == "warning"]
    if header_errors:
        checks.append(
            CheckResult(
                "Header consistency", STATUS_FAIL,
                "; ".join(i.message for i in header_errors),
                "Align User-Agent, Sec-CH-UA and platform headers with one "
                "browser family.",
            )
        )
    elif header_warnings:
        checks.append(
            CheckResult(
                "Header consistency", STATUS_WARN,
                "; ".join(i.message for i in header_warnings),
            )
        )
    else:
        checks.append(
            CheckResult("Header consistency", STATUS_OK, "no contradictions found")
        )
    return checks


def _security_check(client: Any) -> CheckResult:
    verify = bool(getattr(client, "verify", True))
    if verify:
        return CheckResult(
            "Security", STATUS_OK, "certificate verification enabled"
        )
    return CheckResult(
        "Security", STATUS_WARN, "TLS certificate verification is DISABLED",
        "Re-enable verify=True unless you are in a controlled test environment.",
    )


def _fingerprint_checks(
    client: Any, echo_endpoint: str, timeout: float
) -> List[CheckResult]:
    from ..fingerprint import capture as run_capture

    checks: List[CheckResult] = []
    try:
        result = run_capture(
            url=echo_endpoint,
            session=client.session,
            timeout=timeout,
            name="doctor_echo",
        )
        observed = result.fingerprint.to_dict()
    except Exception as exc:
        checks.append(
            CheckResult(
                "Fingerprint observation",
                STATUS_WARN,
                f"echo endpoint failed ({type(exc).__name__}: {exc})",
                "Retry later or choose another echo endpoint.",
            )
        )
        return checks

    ja4 = observed.get("tls", {}).get("ja4")
    if ja4:
        expected = (getattr(client, "_current_profile_data", None) or {}).get("ja4")
        if expected and expected != ja4:
            checks.append(
                CheckResult(
                    "Fingerprint (JA4)",
                    STATUS_WARN,
                    f"observed JA4 differs from profile "
                    f"(observed={ja4}, profile={expected})",
                    "The active backend cannot fully reproduce this profile's TLS "
                    "fingerprint; switch backend or adjust expectations.",
                )
            )
        else:
            checks.append(CheckResult("Fingerprint (JA4)", STATUS_OK, f"observed {ja4}"))

    settings_observed = observed.get("http2", {}).get("settings") or {}
    profile_settings = (getattr(client, "_current_profile_data", None) or {}).get(
        "http2_settings"
    ) or {}
    differing = {
        key: {"observed": settings_observed.get(key), "profile": value}
        for key, value in profile_settings.items()
        if key in settings_observed and settings_observed.get(key) != value
    }
    if differing:
        checks.append(
            CheckResult(
                "HTTP/2 SETTINGS",
                STATUS_WARN,
                f"observed SETTINGS differ from profile: {differing}",
                "Review the HTTP/2 profile differences; the current backend "
                "may not apply custom SETTINGS frames.",
            )
        )
    elif profile_settings and settings_observed:
        checks.append(
            CheckResult("HTTP/2 SETTINGS", STATUS_OK, "match profile")
        )
    else:
        checks.append(
            CheckResult(
                "HTTP/2 SETTINGS", STATUS_SKIP,
                "endpoint did not expose comparable SETTINGS data",
            )
        )
    return checks
