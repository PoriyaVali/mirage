# Mirage agent handoff

## 2026-10-24 - Codex - Reliability source recorded for GitHub review; locally VERIFIED

Implementation and this handoff are recorded together in the review commit on
codex/mirage-reliability-20261024, baseline a922dd58b4ccf838c710de9e4d8ef9006bd54356.
The parent workspace records the resulting commit/PR and hosted CI outcome.
No main merge, version tag, public
release, native app/core adoption, device/server changes or carrier probes.

Exact source changes: .gitattributes,.gitignore,.github/workflows/ci.yml,
README.md,CHANGELOG.md,AI_HANDOFF.md,mirage.go,mirage_test.go,
regression_test.go,framing_test.go,cmd/{miragecheck,sweep}/main.go,
internal/version/version.go,internal/cli/{cli.go,cli_test.go},
internal/probe/{probe.go,probe_test.go,experiment.go,output.go,errors_windows.go,
errors_other.go},tlsdial/{dialer.go,dialer_test.go},
scripts/{build_tools.py,package_release.py},
docs/{measurements-2026-09.md,VALIDATION-2026-10-24.md}.

Final actual Windows race suites PASS on Go1.21.13 and1.27.3:32top-level checks,
61including subtests,4tested packages. vet PASS; fuzz15s/17479exec PASS;20cross-builds
PASS;manifest/21SHAchecks PASS; both actual Windows EXEs version/refused-loopback
JSONL PASS; actionlint/YAML/Python/format/diff PASS. Local binaries identify dirty
baseline explicitly, NOT a clean released commit. No safety/efficacy guarantee.
Validation details and prior failed checks preserved below and in validation doc.
WSL unavailable0x80070422; native Linux and hosted matrix require GitHub CI.
All old carrier measurements archived with original authorship, not claimed as new.

## 2026-10-24 - Codex - Reliability changes IN PROGRESS

User authorized applying the GitHub review. Base a922dd58b4ccf838c710de9e4d8ef9006bd54356,
branch codex/mirage-reliability-20261024. Work is LOCAL and UNCOMMITTED; no release.
Existing historical source and authorship retained. No carrier/device/server tests.

Changed mirage.go: strict record and nested ClientHello boundaries, coalesced tail
preservation, serialized write sequence, atomic replacement/observability state,
zero-length no-op, original-byte progress accounting and terminal transformed-write
errors. Incomplete first writes pass through unchanged; no buffering across calls.
Added regression_test.go from prior isolated audit. Actual go test -race ./... PASS,
including previously red checks and local TLS1.2/1.3. No field efficacy claim.

Added internal/{probe,cli,version}, shared paced/interleaved experiments, typed
TCP/TLS/HTTP failures, applied-shape evidence, text/JSONL/CSV, controls, bounded
verified HTTPS sample, explicit burst mode and build metadata. Command mains
delegate to shared CLI. First race run after package creation PASS (packages
then had no dedicated tests). Added framing_test.go, internal/probe/probe_test.go
and internal/cli/cli_test.go; these new checks NOT RUN yet. CI/package/docs remain
IN PROGRESS. No native adapter or production automatic policy enabled.

Expanded first race run FAILED one Windows TCP refusal-classification test:
Go's Winsock error does not match POSIX ECONNREFUSED. Fixed with typed Windows
WSAECONNREFUSED/WSAECONNRESET helpers plus non-Windows implementation. Rerun
pending; this failure is retained as validation history. First helper attempt
also failed compilation because frozen syscall does not export WSAECONNREFUSED;
replaced with typed syscall.Errno(10061), matching Winsock's defined code.

Corrected expanded Windows race suite PASS, including trusted HTTPS sample,
invalid certificate rejection, typed TCP refusal, controls and all output formats.
Added opt-in tlsdial/{dialer.go,dialer_test.go}: authenticated crypto/tls only,
total/per-attempt bounds, <=1 fresh retry after TLS transport failures, no TCP/
certificate retry or request replay, per-destination/config-scope bounded LRU/TTL,
Reset generation invalidation and coalesced discovery. Dedicated race tests PASS
both learning directions, cached winner, <=2 attempts, reset/TTL/LRU, concurrent
discovery and cancellation/budget. No native core adoption, live policy or carrier
efficacy claimed. CI/release preparation/docs and full final checks still pending.

Added scripts/{build_tools.py,package_release.py}, CI test matrix (minimum1.21,
oldstable/stable Linux, stable Windows), fuzz and both tools on10targets with
manifest/checksum packaging; only tag job publishes. Updated .gitignore/
.gitattributes, README/CHANGELOG; archived prior README without changing its
carrier data in docs/measurements-2026-09.md with explicit prior attribution.
YAML parse, Python compilation and git diff --check PASS. Actionlint pending.
Initial toolchain fetches blocked because inherited GOSUMDB=off; process-local
GOSUMDB=sum.golang.org enabled verification and Go1.21.13/1.27.3 downloads PASS.
No permanent environment changes. WSL list FAILED: service disabled0x80070422;
local native Linux unavailable, hosted CI needed. No service settings changed.
Final supported/minimum tests, fuzz and20cross-builds NOT RUN yet.

Full Windows race suites PASS on verified Go1.21.13 and1.27.3. Actionlint1.7.12
PASS (shellcheck/pyflakes integrations unavailable/disabled, not claimed run).
20cross-builds in progress,16 outputs built so far. Final self-review added TLS
alert and user-verification-callback regressions; both initially FAIL because
net.OpError was too broad and callback EOF looked like transport EOF. Tightened
retry to read/write transport errors and preserve callback error provenance.
Targeted/full policy rerun pending. Source adapter not included in CLI binaries.

Corrected adapter policy race rerun PASS. Added coverage for peer and client
certificate callbacks as well; all verification callback failures retain origin
even when they return EOF. All20cross-builds PASS on Go1.27.3; binaries explicitly
labelled0.3.0-dev/base-a922dd5-dirty, not a tagged source release. Final fuzz/vet/
multi-toolchain rerun and manifest/native-executable checks pending.
Root hiddify-app handoff also tracks this independent checkout. No native core/app
adoption or published release claimed. Do not ship an incomplete candidate.
