# Mirage

Mirage fragments a TLS ClientHello record while preserving the TLS byte stream.
It is a dependency-free Go library plus two measurement commands. Measurements
from August/September 2026 motivated the separate-record-write default; they
are historical observations, not a guarantee about a network today.

Requires Go 1.21 or newer. Release tools are built with the current stable Go.
[Historical measurements and original attribution](docs/measurements-2026-09.md)
and [changes since v0.2.0](CHANGELOG.md).

## Library

```go
import (
    "crypto/tls"
    "github.com/PoriyaVali/mirage"
)

shaped := mirage.NewConn(rawConn, 0) // 0 selects the historical 5-byte default
conn := tls.Client(shaped, &tls.Config{ServerName: "your-server.example"})
if err := conn.Handshake(); err != nil {
    conn.Close()
    // Handle the error; never disable certificate verification to recover.
}
size, applied := shaped.Fragmentation() // actual completed API framing
_, _ = size, applied
```

The first nonempty Write is fragmented only if it starts with one complete,
structurally valid ClientHello record containing a host_name SNI. Two records
leave in separate underlying Write calls. Coalesced bytes after the original
record are sent unchanged; subsequent Writes pass through. Empty Writes are
no-ops. Concurrent methods are safe and the initial sequence cannot interleave
with another Write or become writer-replaceable halfway through.

Incomplete, already fragmented, malformed and non-TLS first inputs pass through
unchanged. The wrapper deliberately does not buffer across Writes. If a TLS
implementation spreads its ClientHello over multiple Writes, Mirage does not
apply; check Fragmentation rather than assuming it did.

A transformed short/error Write reports progress in original-input bytes,
excluding the added record header. That stream becomes terminal: later Writes
return the stored error. Close it and redial; retrying the rest of a partially
transformed frame on the same stream is unsafe.

SplitRecords accepts exactly one complete ClientHello record and returns its
two records separately. Split concatenates them for byte inspection. Neither
accepts trailing records; Conn handles those without modifying them. The
parser validates enclosing record, handshake, extension and SNI vector lengths.
Offsets at or beyond SNI retain the original API's before-name clamping;
Fragmentation reports the applied size, which can differ from the request.

Two API Writes do **not** guarantee two TCP segments. Buffering wrappers, the OS,
offload and the path can change segmentation. Packet-shape claims require
captures on the actual path; see [RFC 9293 section 3.7](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.7).

## Optional adaptive TLS adapter

tlsdial is an opt-in adapter for authenticated standard crypto/tls connections.
It is not automatically installed in an application or a native uTLS/REALITY core.

```go
d, err := tlsdial.New(&tls.Config{ServerName: "your-server.example"}, tlsdial.Options{
    CacheScope: "network-epoch-and-outbound-config",
})
if err != nil { /* handle error */ }
conn, err := d.DialContext(ctx, "tcp", "your-server.example:443")
// On a physical network/configuration change:
d.Reset() // also cancel old in-flight application contexts
```

Import github.com/PoriyaVali/mirage/tlsdial. Defaults are plain first, a 10-second
total budget, a 4-second per-attempt budget, a 10-minute success TTL and 256 LRU
entries. Successful modes are remembered by transport, destination, SNI and
scope/reset generation. Unknown/failing-mode discovery for one destination is
coalesced; established sockets are never shared.

At most one additional fresh connection is attempted after a TLS transport
EOF/reset/timeout. TCP dial errors, certificate failures, protocol alerts and
caller cancellation do not trigger retry. Verification stays enabled and no
application requests are sent or replayed. Reset prevents old discoveries from
repopulating learning; it does not close already returned sockets. Use a new
dialer when TLS configuration/fingerprint changes.

This can cost another connection and more setup time. Carrier rate limits,
battery use and native core adoption still need field validation.

## Measure a path

Choose a fixed endpoint that supports both the test and control names. A control
label does not itself prove a name is allowed or served by that endpoint.

```console
go run ./cmd/miragecheck -addr YOUR_IP:443 -control allowed.example -trials 3 test.example
go run ./cmd/sweep -addr YOUR_IP:443 -control allowed.example -sni test.example
go run ./cmd/sweep -mode repeat -offset 5 -n 3 -addr YOUR_IP:443 -control allowed.example -sni test.example
```

Normal experiments interleave plain/Mirage and control/test observations in
seeded shuffled rounds, with a 15-second pause between attempts. This is a
starting pace, not a universally safe rate. Adjust -delay and back off if
controls degrade. Zero delay requires explicit -burst. Repeat mode also includes
plain and control observations; it does not automatically diagnose rate limiting.

Each result reports the TCP/TLS/optional HTTP stage, typed error, timings, IP
family, Go crypto/tls client identity, requested and actually applied first-record
size. Reset/EOF/timeout are observations, not proof of censorship. TCP failures
are excluded from shape comparisons. A failed control makes comparisons for
that round inconclusive. Unapplied fragmentation is also inconclusive.

By default the commands measure **unauthenticated TLS completion** with
certificate verification disabled, preserving the original probe's purpose.
That result is not authenticated transport, REALITY authentication or successful
proxy traffic. For a supported HTTPS endpoint, use verification and an optional
bounded body sample:

```console
go run ./cmd/miragecheck -addr YOUR_IP:443 -control allowed.example -verify -http-path / test.example
```

-ca roots.pem adds trusted PEM roots and requires -verify. HTTP measurement
reads up to 32 KiB and does not claim completion of a larger download. Native
outbound protocols need their own authenticated end-to-end probes. Changing
the Go toolchain can change the ClientHello; record the client version and
repeat with the real core's fingerprint before applying results there.

Machine-readable output is streamed; JSON uses one event per line:

```console
miragecheck -format json -seed 42 -addr YOUR_IP:443 -control allowed.example test.example
sweep -format csv -addr YOUR_IP:443 -control allowed.example -sni test.example
miragecheck -version
sweep -version
```

JSON/CSV include experiment metadata, individual observations and a summary.
CSV has a fixed header; the metadata_or_summary column holds JSON for those
event types. Version, commit and toolchain identify the binary. -network
selects tcp, tcp4 or tcp6. Ctrl+C cancels the experiment.

Exit codes: 0 for a completed usable experiment; 1 for output/execution errors,
any TCP/control failure or no successful observation; 2 for invalid arguments;
130 for cancellation. Some test-name TLS failures can coexist with exit 0;
inspect observations and inconclusive/control counts instead of treating an
exit code as a censorship verdict.

## Validation and release builds

```console
go vet ./...
go test -race -count=1 ./...
go test -run '^$' -fuzz FuzzSplitRecords -fuzztime 20s -parallel 2 .
python scripts/build_tools.py --output artifacts --version YOUR_VERSION --commit YOUR_SOURCE_COMMIT
python scripts/package_release.py artifacts --version YOUR_VERSION --commit YOUR_SOURCE_COMMIT
python scripts/package_release.py artifacts --verify
```

The build script creates miragecheck and sweep for Linux, Windows, macOS,
Android and router targets. The manifest records each binary's SHA-256, size,
target and build toolchain plus source commit/version; SHA256SUMS covers the 20
binaries and MANIFEST.json. It does not hash itself. Checksums detect corruption;
they are not a publisher signature. Identify uncommitted local builds explicitly.

CI runs native Linux and Windows tests, the declared minimum Go plus supported
oldstable/stable versions, race checks, bounded fuzzing and 20 cross-builds.
Only version tags publish a release. A successful branch build is a candidate,
not a release. v0.2.0 predates the September separate-write correction; check
version/commit when comparing old binaries with current source.

## Limits

Mirage does not encrypt SNI or authenticate the peer. It changes framing that
some historically measured DPI implementations mishandled. It cannot repair
IP blocking, DNS poisoning, a whitelist policy or an unreachable server.
It does not implement QUIC fragmentation and it does not retry application data.

## License

MIT. See [LICENSE](LICENSE). Built for [Doctor Mobile](https://github.com/PoriyaVali).
