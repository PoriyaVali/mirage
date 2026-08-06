# Mirage

Mirage splits a TLS ClientHello across two TLS records so an on-path censor
cannot match on the server name, while the real server reassembles the
handshake normally. It is a few dozen lines, needs no root, no raw sockets and
no kernel help, and it runs anywhere Go runs.

The point of this repository is the **shape** of the split, which was arrived
at by measurement rather than intuition — and which several existing
implementations get backwards.

## The finding

Against Iran's DPI, measured from a datacenter host and a residential mobile
connection, most recently over 680 probes in August 2026:

| first record | result |
|---|---|
| none — send the ClientHello whole | blocked: **reset** on a censored name |
| 1, 2, 4, 5 bytes, both records in one TCP segment | **works** — every censored name completed a TLS 1.3 handshake |
| 3 bytes | dropped |
| 6 bytes and above, up to 64 | dropped |
| the same two records in **two** TCP segments | dropped |
| split inside the server name | dropped |

What makes this work is the **size of the first record**, not where the name
sits. An earlier version of this file claimed the censor stops parsing when the
name is absent from the first record; that was wrong. A 64-byte first record
leaves the name entirely in the second record and is still dropped, so the
censor is not simply failing to find it — a first record small enough makes it
abandon the flow instead.

The safe set is **not contiguous**: 3 fails while 2 and 4 pass, reproducibly,
and identically for a Go and a Chrome client hello. So it is a property of the
censor's parser rather than of any particular byte values.

### The part that can bite you

This censor enforces two independent rules:

1. a censored server name gets a fast **RST**
2. a record layout it dislikes is **silently dropped — even for a name it
   allows**

The second one means a badly chosen first-record size does not merely fail to
evade: it takes the whole connection down, including traffic that would have
been fine. Measure before you pick a value, and prefer the sizes above.

Evasion costs nothing measurable: medians were 286–306 ms across the working
layouts against 310 ms unmodified.

## Why it matters for REALITY

[REALITY](https://github.com/XTLS/REALITY) borrows the identity of a real
site, and that borrowed name travels in the clear. If the censor blocks that
name, the node dies — so operators must hunt for a borrowed site that is both
plausible and unblocked, and re-hunt whenever the blocklist moves.

Fragmenting the ClientHello removes the constraint: the censor stops acting on
that name, so it no longer has to be a host the censor allows. In an end-to-end
test, a REALITY endpoint whose borrowed site was a **blocked** domain was reset
on every attempt without Mirage and carried traffic normally with it.

## Use it as a library

```go
import "github.com/PoriyaVali/mirage"

// Wrap the connection before handing it to your TLS client.
conn = mirage.NewConn(conn, 0) // 0 selects the measured default offset
tlsConn := tls.Client(conn, cfg)
```

`Split` is also exported if you would rather rewrite a buffer yourself. If you
do, write **both records in a single call**. The same two records sent as two
TCP segments were dropped in every measurement, so the layout only survives
while it arrives together.

## Measure your own network

`miragecheck` handshakes with one fixed address while varying only the server
name, so a name that fails plain but succeeds with Mirage isolates SNI-based
interference from routing, DNS or the server.

```console
$ go run ./cmd/miragecheck example.com blocked.example
target 1.1.1.1:443

SERVER NAME                      PLAIN                        MIRAGE
example.com                      ok (tls 0x304)               ok (tls 0x304)
blocked.example                  blocked: reset               ok (tls 0x304)

1 of 1 names that failed plain completed a handshake with Mirage
```

Prebuilt binaries for Linux, Windows, macOS, Android and common router
architectures are attached to each release.

To find the safe sizes on a network rather than assume them, `sweep` walks the
first-record size and repeats each one:

```console
$ go run ./cmd/sweep -sni blocked.example            # which sizes pass
$ go run ./cmd/sweep -mode repeat -offset 5 -n 20    # is one size stable
```

Two habits make the results trustworthy, both learned the hard way:

- **Probe an allowed name in every run.** A layout that fails for a censored
  name *and* for an allowed one was not censored, it was broken — and the two
  are indistinguishable without the control.
- **Run the same binary from an uncensored network.** A bug in your own
  fragmentation code looks exactly like a censorship finding until you see it
  fail somewhere with no censor.

Also worth knowing when reading results: a failure to even establish TCP says
nothing about the layout, since it happens before any of these bytes are sent.
Counting those as failures once made a passing size look unstable here.

## Limits

Mirage hides a server name from a censor that works from a **blocklist**. It
does nothing about:

- **IP-level blocking.** If the address itself is unreachable, no handshake
  trick helps.
- **Whitelist censorship.** Where only approved names are allowed through,
  hiding the name means it matches nothing and is refused by default.
- **DNS poisoning.** Resolve names over a channel the censor does not control.

It also does not encrypt or authenticate anything — it is one layer, meant to
sit under a transport that does.

## License

MIT. See [LICENSE](LICENSE).

Built for [Doctor Mobile](https://github.com/PoriyaVali). Free access to
information, without harm to anyone.
