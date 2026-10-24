package mirage

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// These regression cases reproduced defects in the September source during
// the 2026-10-24 review. They must remain green after the reliability fixes.
func TestAuditCoalescedRecordPreserved(t *testing.T) {
	hello := clientHello("www.example.com")
	tail := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01} // TLS compatibility CCS
	cap := &captureConn{}
	if _, err := NewConn(cap, 0).Write(append(hello, tail...)); err != nil {
		t.Fatal(err)
	}
	wire := cap.buf.Bytes()
	for i := 0; i < 2; i++ {
		if len(wire) < 5 {
			t.Fatal("missing split record")
		}
		size := 5 + int(binary.BigEndian.Uint16(wire[3:5]))
		if size > len(wire) {
			t.Fatal("truncated split record")
		}
		wire = wire[size:]
	}
	if !bytes.Equal(wire, tail) {
		t.Fatalf("trailing TLS record changed or swallowed: got %x, want %x", wire, tail)
	}
}

func TestAuditRejectInvalidLengths(t *testing.T) {
	for _, field := range []string{"record", "handshake", "extensions", "sni_extension", "sni_list", "name_type"} {
		t.Run(field, func(t *testing.T) {
			hello := clientHello("www.example.com")
			nameAt := 5 + IndexSNI(hello[5:])
			switch field {
			case "record":
				binary.BigEndian.PutUint16(hello[3:5], 0)
			case "handshake":
				clear(hello[6:9])
			case "extensions":
				binary.BigEndian.PutUint16(hello[50:52], 0)
			case "sni_extension":
				binary.BigEndian.PutUint16(hello[nameAt-7:nameAt-5], 0)
			case "sni_list":
				binary.BigEndian.PutUint16(hello[nameAt-5:nameAt-3], 0)
			case "name_type":
				hello[nameAt-3] = 1
			}
			if _, _, err := SplitRecords(hello, 0); err == nil {
				t.Fatal("accepted malformed ClientHello; expected ErrNotClientHello")
			}
		})
	}
}

func TestAuditEmptyWriteDoesNotDisable(t *testing.T) {
	cap := &captureConn{}
	conn := NewConn(cap, 0)
	if _, err := conn.Write(nil); err != nil {
		t.Fatal(err)
	}
	cap.writes = 0
	if _, err := conn.Write(clientHello("www.example.com")); err != nil {
		t.Fatal(err)
	}
	if cap.writes != 2 {
		t.Fatalf("zero-length Write disabled fragmentation; got %d writes", cap.writes)
	}
}

type auditPartialConn struct {
	net.Conn
	calls    int
	accepted int
}

func (c *auditPartialConn) Write(b []byte) (int, error) {
	c.calls++
	if c.calls == 2 {
		c.accepted += 3
		return 3, io.ErrClosedPipe
	}
	c.accepted += len(b)
	return len(b), nil
}

func TestAuditPartialWriteCount(t *testing.T) {
	raw := &auditPartialConn{}
	n, err := NewConn(raw, 0).Write(clientHello("www.example.com"))
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("error = %v", err)
	}
	if n == 0 {
		t.Fatalf("reported 0 original bytes after accepting %d wire bytes", raw.accepted)
	}
}

type auditDiscardConn struct{ net.Conn }

func (c *auditDiscardConn) Write(b []byte) (int, error) { return len(b), nil }

func TestAuditConcurrentWrites(t *testing.T) {
	for i := 0; i < 128; i++ {
		conn := NewConn(&auditDiscardConn{}, 0)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for j := 0; j < 2; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if _, err := conn.Write([]byte("ordinary bytes")); err != nil {
					t.Error(err)
				}
			}()
		}
		close(start)
		wg.Wait()
	}
}

func TestAuditRealTLSLoopback(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			server := httptest.NewUnstartedServer(nil)
			server.TLS = &tls.Config{MinVersion: version, MaxVersion: version}
			server.StartTLS()
			defer server.Close()
			raw, err := net.DialTimeout("tcp", server.Listener.Addr().String(), 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			if err := raw.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			conn := tls.Client(NewConn(raw, 0), &tls.Config{
				ServerName: "example.com", InsecureSkipVerify: true,
				MinVersion: version, MaxVersion: version,
			})
			if err := conn.Handshake(); err != nil {
				t.Fatal(err)
			}
			if conn.ConnectionState().Version != version {
				t.Fatal("wrong TLS version")
			}
			_ = conn.Close()
		})
	}
}
