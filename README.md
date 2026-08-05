# Mirage

Mirage splits a TLS ClientHello across two TLS records so an on-path censor
cannot match on the server name, while the real server reassembles the
handshake normally. It is a few dozen lines, needs no root, no raw sockets and
no kernel help, and it runs anywhere Go runs.

The point of this repository is the **shape** of the split, which was arrived
at by measurement rather than intuition — and which several existing
implementations get backwards.

## The finding

Against Iran's DPI, measured from two vantage points in August 2026:

| technique | result |
|---|---|
| Split the ClientHello across TCP segments | **fails** — this censor reassembles the TCP stream before matching |
| Split the TLS record at a random point **inside** the server name | **fails** — dropped even for a hostname that is otherwise allowed |
| One small first record ending **before** the server name, name intact in the second, both in one TCP segment | **works** |

The censor parses only the first TLS record looking for a ClientHello server
name. When the name is not there it stops looking instead of reassembling the
records, so the handshake goes through. Splitting inside the name leaves a
fragment of it in the first record and the connection dies; splitting at the
TCP layer does nothing at all.

Every server name that was reset without Mirage completed a full TLS 1.3
handshake with it, from a datacenter host and from a residential mobile
connection.

## Why it matters for REALITY

[REALITY](https://github.com/XTLS/REALITY) borrows the identity of a real
site, and that borrowed name travels in the clear. If the censor blocks that
name, the node dies — so operators must hunt for a borrowed site that is both
plausible and unblocked, and re-hunt whenever the blocklist moves.

Fragmenting the ClientHello removes the constraint: the censor never sees the
borrowed name, so it no longer has to be a host the censor allows. In an
end-to-end test, a REALITY endpoint whose borrowed site was a **blocked**
domain was reset on every attempt without Mirage and carried traffic normally
with it.

## Use it as a library

```go
import "github.com/PoriyaVali/mirage"

// Wrap the connection before handing it to your TLS client.
conn = mirage.NewConn(conn, 0) // 0 selects the measured default offset
tlsConn := tls.Client(conn, cfg)
```

`Split` is also exported if you would rather rewrite a buffer yourself.

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
