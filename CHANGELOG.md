# Changes

## Unreleased reliability update after v0.2.0

- Preserve coalesced TLS record tails, validate nested lengths and pass unsupported
  partial inputs through unchanged. Split/SplitRecords now require exactly one
  complete record; use Conn for coalesced inputs.
- Synchronize initial writes and replacement state, ignore empty writes, report
  transformed partial-write progress and prevent continuation of damaged frames.
- Retain the September separate-record-write correction absent from v0.2.0.
  Application writes do not promise TCP packet boundaries.
- Add regression/property tests, real TLS/verified HTTPS fixtures and native
  Windows/Linux/minimum/supported-Go CI coverage.
- Replace causal "blocked"/burst verdicts with typed TCP/TLS/HTTP observations,
  actual applied-shape evidence and control-aware paired summaries.
- CLI output and defaults change: three interleaved rounds, control name,
  15-second pacing, explicit unpaced -burst, text/JSONL/CSV, certificate/HTTP
  options, cancellation and documented exit codes. Existing table parsers must
  migrate to structured output. No generic TLS result proves proxy authentication.
- Add opt-in tlsdial for standard authenticated crypto/tls, bounded last-success
  learning and at most one fresh transport-failure retry. No native core policy
  is enabled automatically; no carrier-effectiveness claim is made.
- Package both tools on all ten targets with version/commit/toolchain metadata,
  a 20-binary manifest and SHA256SUMS. Publication still requires a version tag.

The August/September measurement record is preserved in docs/measurements-2026-09.md.
