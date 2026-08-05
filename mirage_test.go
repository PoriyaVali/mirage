package mirage

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// captureConn records what was written and how many Write calls it took, so a
// test can assert that both records leave in a single segment.
type captureConn struct {
	net.Conn
	buf    bytes.Buffer
	writes int
}

func (c *captureConn) Write(b []byte) (int, error) {
	c.writes++
	return c.buf.Write(b)
}

// TestShape locks in the shape that was measured to work: exactly two records
// in one segment, the first ending before the server name, the name intact in
// the second.
func TestShape(t *testing.T) {
	hello := clientHello("www.example.com")
	cap := &captureConn{}

	n, err := NewConn(cap, 0).Write(hello)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(hello) {
		t.Fatalf("Write reported %d, want the caller's length %d", n, len(hello))
	}
	if cap.writes != 1 {
		t.Fatalf("both records must leave in one segment, got %d writes", cap.writes)
	}

	records := parseRecords(t, cap.buf.Bytes())
	if len(records) != 2 {
		t.Fatalf("want 2 records, got %d", len(records))
	}
	if len(records[0]) != DefaultOffset {
		t.Errorf("first record is %d bytes, want the small pre-SNI slice of %d", len(records[0]), DefaultOffset)
	}
	if strings.Contains(string(records[0]), "www.example.com") {
		t.Error("the server name must NOT be in the first record; that is the whole point")
	}
	if !strings.Contains(string(records[1]), "www.example.com") {
		t.Error("the server name must stay intact in the second record; splitting inside it was measured to be dropped")
	}
	if got := append(records[0], records[1]...); !bytes.Equal(got, hello[recordHeaderLen:]) {
		t.Error("concatenated records must reproduce the original handshake byte for byte")
	}
}

// TestPassThrough makes sure ordinary traffic is never rewritten.
func TestPassThrough(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"not tls", []byte("plain bytes")},
		{"short", []byte{recordHandshake, 0x03, 0x01}},
		{"handshake without sni", func() []byte {
			h := clientHello("x")
			// Truncate the extensions away so no server name can be found.
			return h[:recordHeaderLen+45]
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cap := &captureConn{}
			if _, err := NewConn(cap, 0).Write(tc.in); err != nil {
				t.Fatalf("write: %v", err)
			}
			if !bytes.Equal(cap.buf.Bytes(), tc.in) {
				t.Error("input must be forwarded untouched")
			}
		})
	}
}

// TestOnlyFirstWriteIsSplit checks that application data after the handshake is
// left alone.
func TestOnlyFirstWriteIsSplit(t *testing.T) {
	cap := &captureConn{}
	conn := NewConn(cap, 0)
	if _, err := conn.Write(clientHello("www.example.com")); err != nil {
		t.Fatalf("write: %v", err)
	}
	cap.buf.Reset()
	payload := []byte("application data")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(cap.buf.Bytes(), payload) {
		t.Error("writes after the ClientHello must pass through untouched")
	}
}

func TestIndexSNI(t *testing.T) {
	hs := clientHello("host.example")[recordHeaderLen:]
	at := IndexSNI(hs)
	if at < 0 {
		t.Fatal("server name not found")
	}
	if got := string(hs[at : at+len("host.example")]); got != "host.example" {
		t.Errorf("IndexSNI pointed at %q", got)
	}
}

// TestIndexSNIRejectsTruncated feeds every truncation of a valid hello to the
// parser; none may panic or report a name past the buffer.
func TestIndexSNIRejectsTruncated(t *testing.T) {
	hs := clientHello("host.example")[recordHeaderLen:]
	for i := 0; i < len(hs); i++ {
		at := IndexSNI(hs[:i])
		if at > i {
			t.Fatalf("truncation at %d reported an out-of-range index %d", i, at)
		}
	}
}

func parseRecords(t *testing.T, b []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for len(b) > 0 {
		if len(b) < recordHeaderLen {
			t.Fatal("truncated record header")
		}
		if b[0] != recordHandshake {
			t.Fatalf("expected a handshake record, got 0x%02x", b[0])
		}
		n := int(binary.BigEndian.Uint16(b[3:5]))
		if len(b) < recordHeaderLen+n {
			t.Fatal("truncated record body")
		}
		out = append(out, b[recordHeaderLen:recordHeaderLen+n])
		b = b[recordHeaderLen+n:]
	}
	return out
}

// clientHello builds a structurally valid ClientHello record carrying the
// given server name.
func clientHello(sni string) []byte {
	name := []byte(sni)
	var ext []byte
	ext = binary.BigEndian.AppendUint16(ext, extServerName)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(name)+5))
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(name)+3))
	ext = append(ext, 0x00)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(name)))
	ext = append(ext, name...)

	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, bytes.Repeat([]byte{0x41}, 32)...)
	body = append(body, 0x00)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = append(body, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	hs := []byte{handshakeHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	rec := []byte{recordHandshake, 0x03, 0x01}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}
