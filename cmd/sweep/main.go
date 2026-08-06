// Command sweep probes how a censor treats a fragmented ClientHello.
//
// Two modes:
//
//	-mode table   vary the size of the small first TLS record
//	-mode repeat  hold one size and repeat, to expose rate limiting
//
// The repeat mode matters: a censor that punishes a burst of connections looks
// exactly like a size-dependent result if you only sweep once.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/PoriyaVali/mirage"
)

func attempt(addr, sni string, offset int, timeout time.Duration) bool {
	raw, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))
	var conn net.Conn = raw
	if offset > 0 {
		conn = mirage.NewConn(raw, offset)
	}
	c := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	return c.Handshake() == nil
}

func main() {
	addr := flag.String("addr", "1.1.1.1:443", "reachable host:port")
	mode := flag.String("mode", "table", "table | repeat")
	sni := flag.String("sni", "www.instagram.com", "server name to probe with")
	offset := flag.Int("offset", 5, "first-record size for repeat mode")
	n := flag.Int("n", 20, "iterations for repeat mode")
	delay := flag.Duration("delay", 0, "pause between attempts")
	trials := flag.Int("trials", 3, "attempts per cell in table mode")
	timeout := flag.Duration("timeout", 8*time.Second, "per-attempt timeout")
	flag.Parse()

	switch *mode {
	case "repeat":
		fmt.Printf("offset=%d sni=%s delay=%s - %d attempts in a row\n", *offset, *sni, *delay, *n)
		fmt.Print("  ")
		ok := 0
		for i := 0; i < *n; i++ {
			if attempt(*addr, *sni, *offset, *timeout) {
				ok++
				fmt.Print(".")
			} else {
				fmt.Print("X")
			}
			time.Sleep(*delay)
		}
		fmt.Printf("\n  %d/%d succeeded   ('.' = handshake, 'X' = blocked)\n", ok, *n)
		if ok < *n {
			fmt.Println("  failures in a run of one fixed size mean the censor reacts to the burst,")
			fmt.Println("  not to the size - so a single sweep cannot be trusted.")
		}
	default:
		offsets := []int{0, 1, 2, 3, 4, 5, 8, 12, 16, 24, 32, 64}
		// Shuffle so a burst penalty cannot masquerade as a size effect.
		rand.Shuffle(len(offsets), func(i, j int) { offsets[i], offsets[j] = offsets[j], offsets[i] })
		fmt.Printf("target %s sni=%s trials=%d delay=%s (order shuffled)\n\n", *addr, *sni, *trials, *delay)
		type row struct {
			off, ok int
		}
		var rows []row
		for _, off := range offsets {
			ok := 0
			for i := 0; i < *trials; i++ {
				if attempt(*addr, *sni, off, *timeout) {
					ok++
				}
				time.Sleep(*delay)
			}
			rows = append(rows, row{off, ok})
			label := fmt.Sprintf("%d", off)
			if off == 0 {
				label = "none"
			}
			fmt.Printf("  first=%-5s %d/%d\n", label, ok, *trials)
		}
	}
}
