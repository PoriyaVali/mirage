package mirage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
)

type scriptedConn struct {
	net.Conn
	calls, failCall, take int
	failure               error
}

func (c *scriptedConn) Write(b []byte) (int, error) {
	c.calls++
	if c.calls == c.failCall {
		return c.take, c.failure
	}
	return len(b), nil
}

func TestPartialFramesAreTerminal(t *testing.T) {
	hello := clientHello("www.example.com")
	first, second, err := SplitRecords(hello, 0)
	if err != nil {
		t.Fatal(err)
	}
	tail := []byte{0x14, 3, 3, 0, 1, 1}
	for _, tc := range []struct {
		name             string
		call, take, want int
		err              error
	}{
		{"first_header", 1, 3, 3, io.ErrClosedPipe},
		{"first_payload", 1, len(first) - 1, len(first) - 1, io.ErrClosedPipe},
		{"second_header", 2, 3, len(first), io.ErrClosedPipe},
		{"second_payload", 2, 7, len(first) + 2, io.ErrClosedPipe},
		{"tail", 3, 2, len(hello) + 2, io.ErrClosedPipe},
		{"short_without_error", 2, len(second) - 1, len(hello) - 1, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := &scriptedConn{failCall: tc.call, take: tc.take, failure: tc.err}
			conn := NewConn(raw, 0)
			n, err := conn.Write(append(append([]byte{}, hello...), tail...))
			wantErr := tc.err
			if wantErr == nil {
				wantErr = io.ErrShortWrite
			}
			if n != tc.want || !errors.Is(err, wantErr) {
				t.Fatalf("got (%d,%v), want (%d,%v)", n, err, tc.want, wantErr)
			}
			calls := raw.calls
			if n, err = conn.Write([]byte("retry")); n != 0 || !errors.Is(err, wantErr) || raw.calls != calls {
				t.Fatalf("terminal error allowed retry: n=%d err=%v calls=%d", n, err, raw.calls)
			}
			if conn.WriterReplaceable() {
				t.Fatal("failed stream must not be replaceable")
			}
		})
	}
}

type gatedConn struct {
	net.Conn
	mu      sync.Mutex
	writes  [][]byte
	entered chan struct{}
	release chan struct{}
}

func (c *gatedConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte{}, b...))
	first := len(c.writes) == 1
	c.mu.Unlock()
	if first {
		close(c.entered)
		<-c.release
	}
	return len(b), nil
}

func TestInitialSequenceCannotBeBypassed(t *testing.T) {
	raw := &gatedConn{entered: make(chan struct{}), release: make(chan struct{})}
	conn := NewConn(raw, 0)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := conn.Write(clientHello("example.com")); err != nil {
			t.Error(err)
		}
	}()
	<-raw.entered
	if conn.WriterReplaceable() {
		close(raw.release)
		wg.Wait()
		t.Fatal("replaceable while first record is blocked")
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := conn.Write([]byte("later")); err != nil {
			t.Error(err)
		}
	}()
	close(raw.release)
	wg.Wait()
	if len(raw.writes) != 3 || !bytes.Equal(raw.writes[2], []byte("later")) {
		t.Fatalf("interleaved records: %x", raw.writes)
	}
	if !conn.WriterReplaceable() {
		t.Fatal("completed sequence is not replaceable")
	}
	if size, ok := conn.Fragmentation(); !ok || size != DefaultOffset {
		t.Fatalf("fragmentation=(%d,%v)", size, ok)
	}
}

func TestIncompleteWritesPassThroughUnchanged(t *testing.T) {
	hello := clientHello("example.com")
	for split := 1; split < len(hello); split++ {
		raw := &captureConn{}
		conn := NewConn(raw, 0)
		if _, err := conn.Write(hello[:split]); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(hello[split:]); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(raw.buf.Bytes(), hello) {
			t.Fatalf("split %d changed bytes", split)
		}
		if _, ok := conn.Fragmentation(); ok {
			t.Fatalf("split %d falsely reported fragmentation", split)
		}
	}
}

func paddedHello(size int) []byte {
	hello := clientHello("example.com")
	padding := size - (len(hello) - 5) - 4
	hello = append(hello, 0, 21, byte(padding>>8), byte(padding))
	hello = append(hello, make([]byte, padding)...)
	binary.BigEndian.PutUint16(hello[50:52], uint16(len(hello)-52))
	n := len(hello) - 9
	hello[6], hello[7], hello[8] = byte(n>>16), byte(n>>8), byte(n)
	binary.BigEndian.PutUint16(hello[3:5], uint16(len(hello)-5))
	return hello
}

func TestLargeAndMalformedRecords(t *testing.T) {
	for _, size := range []int{4096, maxPlaintextLen} {
		hello := paddedHello(size)
		first, second, err := SplitRecords(hello, 0)
		if err != nil || !bytes.Equal(append(first[5:], second[5:]...), hello[5:]) {
			t.Fatalf("size %d: %v", size, err)
		}
	}
	oversized := paddedHello(maxPlaintextLen + 1)
	if _, _, err := SplitRecords(oversized, 0); err == nil {
		t.Fatal("accepted oversized record")
	}
	hello := clientHello("example.com")
	// A malformed extension after a valid SNI must not be ignored.
	hello = append(hello, 0xff)
	binary.BigEndian.PutUint16(hello[50:52], uint16(len(hello)-52))
	n := len(hello) - 9
	hello[6], hello[7], hello[8] = byte(n>>16), byte(n>>8), byte(n)
	binary.BigEndian.PutUint16(hello[3:5], uint16(len(hello)-5))
	raw := &captureConn{}
	if _, err := NewConn(raw, 0).Write(hello); err != nil {
		t.Fatal(err)
	}
	if raw.writes != 1 || !bytes.Equal(raw.buf.Bytes(), hello) {
		t.Fatal("malformed input was rewritten")
	}
}

func FuzzSplitRecords(f *testing.F) {
	f.Add(clientHello("example.com"), 5)
	f.Add(paddedHello(4096), 64)
	f.Add([]byte{0x16, 3, 1, 0, 0}, 0)
	f.Fuzz(func(t *testing.T, input []byte, offset int) {
		original := append([]byte{}, input...)
		first, second, err := SplitRecords(input, offset)
		if !bytes.Equal(input, original) {
			t.Fatal("mutated input")
		}
		if err != nil {
			return
		}
		for _, record := range [][]byte{first, second} {
			if len(record) < 6 || len(record)-5 > maxPlaintextLen || int(binary.BigEndian.Uint16(record[3:5])) != len(record)-5 {
				t.Fatal("invalid output record")
			}
			if !bytes.Equal(record[:3], input[:3]) {
				t.Fatal("changed record type/version")
			}
		}
		if !bytes.Equal(append(first[5:], second[5:]...), input[5:]) {
			t.Fatal("changed handshake stream")
		}
		if len(first)-5 >= IndexSNI(input[5:]) {
			t.Fatal("split reached the server name")
		}
	})
}
