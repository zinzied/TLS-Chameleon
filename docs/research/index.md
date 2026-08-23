# TLS-Chameleon Research Notes

This directory holds protocol and fingerprint **analyses produced with
TLS-Chameleon's own tooling** (capture, diff, similarity, benchmarks).
Everything here is derived from real runs; where a claim is environment-
specific it says so. This is the differentiator: a normal HTTP client ships
no research.

| Note | Topic | Tooling used |
|---|---|---|
| [`ja4-family-signatures.md`](ja4-family-signatures.md) | Observed JA4 differences between Chrome- and Firefox-shaped stacks | `fingerprint.capture` |
| [`http2-settings-comparison.md`](http2-settings-comparison.md) | H2 SETTINGS variance across profile families in the built-in gallery | gallery + `diff_fingerprints` |
| [`../BENCHMARK_SNAPSHOT.md`](../BENCHMARK_SNAPSHOT.md) | Backend performance comparison (labeled machine-specific) | `chameleon benchmark` |
| [`../BENCHMARK_METHODOLOGY.md`](../BENCHMARK_METHODOLOGY.md) | How benchmark numbers are produced | — |

## Reproducing any note

Each note states its capture parameters. Re-run with:

```bash
chameleon inspect https://tls.peet.ws/api/clean --json > my_capture.json
chameleon diff docs/research/data/chrome_native.json my_capture.json
```

Contributions adding captures on other OS/stack combinations are welcome —
that is precisely how the profile verification backlog shrinks.
