# Reliability candidate validation - 2026-10-24

Agent: Codex. Baseline: a922dd58b4ccf838c710de9e4d8ef9006bd54356.
This records local validation of the proposed reliability changes. It is not a
carrier measurement, a native core integration report or a published release.

| Check | Actual result |
|---|---|
| Windows amd64, Go 1.21.13, full race suite | PASS: 32 top-level checks / 61 including subtests in four tested packages |
| Windows amd64, Go 1.27.3, full race suite | PASS: same 32 / 61 checks |
| Go 1.27.3 go vet ./... | PASS |
| Go 1.27.3 FuzzSplitRecords, two workers, 15-second budget | PASS: 17,479 executions, no failing corpus; elapsed 16s |
| Both commands on all ten target combinations | PASS: 20 CGO-disabled cross-builds |
| Manifest/build-stamp agreement and SHA-256 verification | PASS: 20 binaries plus manifest / 21 checksums |
| Actual Windows EXEs, version metadata and refused-loopback TCP in JSONL | PASS for miragecheck and sweep; four TCP failures, zero comparable pairs, exit 1 |
| Workflow actionlint 1.7.12 | PASS; optional shellcheck/pyflakes integrations were disabled and not claimed |
| YAML parsing, Python compilation, formatting and diff whitespace | PASS |

The tests cover coalesced CCS preservation, strict nested lengths, partial
initial writes, empty writes, terminal transformed errors and byte accounting,
concurrent/replacement sequencing, large records, TLS 1.2/1.3, trusted HTTPS data,
certificate rejection, staged probe errors/controls/outputs, both adaptive learning
directions, TTL/LRU/reset, coalesced discovery, cancellation and total deadlines.
Returned TLS connections carry authenticated application data after the setup
context ends. Protocol alerts and all three certificate-related callbacks do not
trigger retries, even when a callback returns EOF. No application request is
sent or replayed by adaptive dialing.

Validation exposed and corrected two implementation issues before submission:

- Windows uses Winsock refusal code 10061 rather than POSIX ECONNREFUSED. The
  first expanded suite failed that classification; an attempted exported syscall
  constant also failed compilation. Typed platform-specific handling fixed both.
- A self-review regression found TLS remote alerts and user callback EOF were
  eligible for retry. Both tests initially failed, then passed after transport
  operations were narrowed and callback error provenance was preserved. The
  final complete suites above include those corrections.

Local cross-builds identify themselves as 0.3.0-dev with the baseline SHA plus
the explicit -dirty suffix. They are review artifacts from an uncommitted source
candidate, not binaries of v0.2.0 or an invented clean source tag. CI embeds its
actual checked-out commit and current toolchain in future candidate/release builds.

Local native Linux execution was unavailable: WSL listing failed with disabled
service error 0x80070422. No WSL/service configuration was changed. The workflow
adds native Linux minimum/oldstable/stable and Windows stable runs; hosted results
must be checked separately after pushing. Cross-compilation is not native testing.

Toolchain downloads initially failed because inherited GOSUMDB was off. They
succeeded with checksum verification enabled in child-process environments only;
no permanent user environment setting was changed.

Unresolved field scope: no new MCI/Irancell/fixed-network, physical Android,
router or public endpoint probes; no uTLS/REALITY core adoption, battery/rate-limit
measurement, production rollout or publisher signing. The historical measurement
archive retains its original attribution and must not be read as today's result.
