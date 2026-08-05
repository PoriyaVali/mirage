// Command miragecheck measures how a network path treats TLS server names.
//
// It opens a TLS handshake to one fixed, reachable address while varying only
// the server name, first normally and then with Mirage's record
// fragmentation. Because the address never changes, a name that fails plain
// but succeeds with Mirage isolates SNI-based interference from anything else
// (routing, DNS, the server itself).
//
//	miragecheck -addr 1.1.1.1:443 example.com blocked.example
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/PoriyaVali/mirage"
)

func main() {
	addr := flag.String("addr", "1.1.1.1:443", "reachable host:port to handshake against; only the server name varies")
	timeout := flag.Duration("timeout", 8*time.Second, "per-attempt timeout")
	offset := flag.Int("offset", 0, "bytes of the handshake kept in the first record (0 = default)")
	flag.Parse()

	names := flag.Args()
	if len(names) == 0 {
		fmt.Fprintln(os.Stderr, "usage: miragecheck [-addr host:port] <server-name>...")
		os.Exit(2)
	}

	fmt.Printf("target %s\n\n%-32s %-28s %s\n", *addr, "SERVER NAME", "PLAIN", "MIRAGE")
	var blocked, rescued int
	for _, name := range names {
		plain := probe(*addr, name, *timeout, false, *offset)
		mir := probe(*addr, name, *timeout, true, *offset)
		fmt.Printf("%-32s %-28s %s\n", name, plain, mir)
		if !strings.HasPrefix(plain, "ok") {
			blocked++
			if strings.HasPrefix(mir, "ok") {
				rescued++
			}
		}
	}
	fmt.Printf("\n%d of %d names that failed plain completed a handshake with Mirage\n", rescued, blocked)
}

func probe(addr, serverName string, timeout time.Duration, useMirage bool, offset int) string {
	raw, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "tcp: " + short(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))

	var conn net.Conn = raw
	if useMirage {
		conn = mirage.NewConn(raw, offset)
	}
	// InsecureSkipVerify: we are measuring whether the handshake is allowed to
	// happen at all, not authenticating the peer.
	c := tls.Client(conn, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	if err := c.Handshake(); err != nil {
		return "blocked: " + short(err)
	}
	return fmt.Sprintf("ok (tls 0x%x)", c.ConnectionState().Version)
}

func short(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "reset by peer"):
		return "reset"
	case strings.Contains(s, "timeout"), strings.Contains(s, "deadline"):
		return "timeout"
	case strings.Contains(s, "EOF"):
		return "eof"
	}
	if i := strings.LastIndex(s, ": "); i >= 0 {
		s = s[i+2:]
	}
	if len(s) > 22 {
		s = s[:22]
	}
	return s
}
