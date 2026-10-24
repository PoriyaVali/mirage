// Package mirage fragments a complete initial TLS ClientHello record.
// Separate record writes are the default measured on MCI and Irancell in
// September 2026. These observations are network- and time-specific; neither
// record sizes nor application Write boundaries guarantee a TCP packet shape.
package mirage

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

const (
	recordHeaderLen = 5
	maxPlaintextLen = 1 << 14
	handshakeHello  = 0x01
	recordHandshake = 0x16
	extServerName   = 0x0000

	// DefaultOffset keeps the handshake header and one more byte in the
	// first record. It is a historical default, not a universal safe size.
	DefaultOffset = 5
)

// ErrNotClientHello means the input is not exactly one complete, structurally
// valid TLS ClientHello record containing a host_name SNI.
var ErrNotClientHello = errors.New("mirage: not a splittable ClientHello")

// MeasuredSafeSizes records August 2026 observations, not current guarantees.
// Measure your own path with controls before selecting a size.
var MeasuredSafeSizes = []int{1, 2, 4, 5}

// Conn fragments the first nonempty Write only when it starts with a complete
// ClientHello record. Any following bytes in that Write are preserved.
// Incomplete, already fragmented, malformed and non-TLS inputs pass through
// unchanged. There is no buffering across Writes, so partial inputs cannot
// deadlock a caller waiting for its Write to complete.
//
// Concurrent methods are safe. A failed transformed Write is terminal: later
// Writes return that error without sending more bytes; callers must close the
// connection and establish a new stream rather than retry a partial frame.
type Conn struct {
	net.Conn
	offset       int
	writeMu      sync.Mutex
	firstWritten bool
	writeErr     error
	replaceable  atomic.Bool
	appliedSize  atomic.Int64
}

// NewConn returns a wrapper. An offset <= 0 selects DefaultOffset.
func NewConn(conn net.Conn, offset int) *Conn {
	if offset <= 0 {
		offset = DefaultOffset
	}
	return &Conn{Conn: conn, offset: offset}
}

func (c *Conn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.firstWritten {
		return c.Conn.Write(b)
	}
	c.firstWritten = true

	end := 0
	if len(b) >= recordHeaderLen {
		end = recordHeaderLen + int(binary.BigEndian.Uint16(b[3:5]))
	}
	var first, second []byte
	err := ErrNotClientHello
	if end > recordHeaderLen && end <= len(b) {
		first, second, err = SplitRecords(b[:end], c.offset)
	}
	if err != nil {
		n, err := c.Conn.Write(b)
		c.replaceable.Store(true)
		return n, err
	}

	// Keep these calls separate. This preserves the measured API write shape;
	// TCP segmentation still depends on the OS, wrappers and network path.
	n, err := c.writeRecord(first)
	if err != nil {
		return n, err
	}
	written := n // the first record header replaces the original header
	n, err = c.writeRecord(second)
	// The second header is new framing, not caller data.
	if n > recordHeaderLen {
		written += n - recordHeaderLen
	}
	if err != nil {
		return written, err
	}
	c.appliedSize.Store(int64(len(first) - recordHeaderLen))
	if end < len(b) {
		n, err = c.writeRecord(b[end:])
		written += n
		if err != nil {
			return written, err
		}
	}
	c.replaceable.Store(true)
	return written, nil
}

func (c *Conn) writeRecord(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n < 0 || n > len(b) {
		n = 0
		err = io.ErrShortWrite
	}
	if n < len(b) && err == nil {
		err = io.ErrShortWrite
	}
	if err != nil {
		c.writeErr = err
	}
	return n, err
}

func (c *Conn) ReaderReplaceable() bool { return true }

// WriterReplaceable becomes true only after the initial sequence finishes.
// It remains false after a failed transformed Write.
func (c *Conn) WriterReplaceable() bool { return c.replaceable.Load() }
func (c *Conn) Upstream() any           { return c.Conn }

// Fragmentation reports the actual first-record payload size after both split
// records were completely written. Zero/false means fragmentation was not
// completed. This is API framing evidence, not a packet-capture result.
func (c *Conn) Fragmentation() (size int, applied bool) {
	size = int(c.appliedSize.Load())
	return size, size != 0
}

// Split returns the two records concatenated. It accepts exactly one complete
// record. To retain separate API writes, use SplitRecords instead.
func Split(record []byte, offset int) ([]byte, error) {
	first, second, err := SplitRecords(record, offset)
	if err != nil {
		return nil, err
	}
	return append(first, second...), nil
}

// SplitRecords accepts exactly one complete ClientHello record, checks its
// nested lengths, and returns two records with the original handshake bytes.
// Conn handles coalesced trailing records separately. An excessive offset is
// moved before the name, preserving the original API's clamping behavior.
func SplitRecords(record []byte, offset int) ([]byte, []byte, error) {
	if offset <= 0 {
		offset = DefaultOffset
	}
	if len(record) <= recordHeaderLen || record[0] != recordHandshake ||
		record[1] != 3 || record[2] > 3 {
		return nil, nil, ErrNotClientHello
	}
	length := int(binary.BigEndian.Uint16(record[3:5]))
	if length > maxPlaintextLen || length != len(record)-recordHeaderLen {
		return nil, nil, ErrNotClientHello
	}
	handshake := record[recordHeaderLen:]
	sni := IndexSNI(handshake)
	if sni < 0 {
		return nil, nil, ErrNotClientHello
	}
	if offset >= sni {
		offset = sni / 2
	}
	if offset <= 0 || offset >= len(handshake) {
		return nil, nil, ErrNotClientHello
	}
	first := appendRecord(make([]byte, 0, recordHeaderLen+offset), record[:3], handshake[:offset])
	second := appendRecord(make([]byte, 0, recordHeaderLen+len(handshake)-offset), record[:3], handshake[offset:])
	return first, second, nil
}

func appendRecord(dst, headerPrefix, payload []byte) []byte {
	dst = append(dst, headerPrefix...)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(payload)))
	return append(dst, payload...)
}

// IndexSNI returns the hostname's offset in one complete ClientHello handshake
// message, or -1. All enclosing lengths and the entire extension block must be
// valid, even when SNI occurs before a malformed later extension.
func IndexSNI(hs []byte) int {
	if len(hs) < 4 || hs[0] != handshakeHello ||
		int(hs[1])<<16|int(hs[2])<<8|int(hs[3]) != len(hs)-4 {
		return -1
	}
	r := reader{b: hs, pos: 4}
	if !r.skip(2 + 32) { // legacy_version + random
		return -1
	}
	session, ok := r.vector(1)
	if !ok || len(session) > 32 {
		return -1
	}
	ciphers, ok := r.vector(2)
	if !ok || len(ciphers) == 0 || len(ciphers)%2 != 0 {
		return -1
	}
	compression, ok := r.vector(1)
	if !ok || len(compression) == 0 {
		return -1
	}
	extensions, ok := r.vector(2)
	if !ok || r.remaining() != 0 {
		return -1
	}
	base := r.pos - len(extensions)
	ext := reader{b: extensions}
	nameAt := -1
	for ext.remaining() > 0 {
		kind, ok := ext.uint16()
		if !ok {
			return -1
		}
		body, ok := ext.vector(2)
		if !ok {
			return -1
		}
		if kind != extServerName {
			continue
		}
		if nameAt >= 0 {
			return -1 // duplicate server_name extension
		}
		sni := reader{b: body}
		names, ok := sni.vector(2)
		if !ok || len(names) == 0 || sni.remaining() != 0 {
			return -1
		}
		list := reader{b: names}
		for list.remaining() > 0 {
			kind, ok := list.byte()
			if !ok || kind != 0 || nameAt >= 0 {
				return -1 // only host_name is supported, at most once
			}
			name, ok := list.vector(2)
			if !ok || len(name) == 0 {
				return -1
			}
			nameAt = base + ext.pos - len(body) + 2 + list.pos - len(name)
		}
	}
	return nameAt
}

type reader struct {
	b   []byte
	pos int
}

func (r *reader) remaining() int { return len(r.b) - r.pos }

func (r *reader) skip(n int) bool {
	if n < 0 || r.remaining() < n {
		return false
	}
	r.pos += n
	return true
}

func (r *reader) byte() (byte, bool) {
	if r.remaining() < 1 {
		return 0, false
	}
	v := r.b[r.pos]
	r.pos++
	return v, true
}

func (r *reader) uint16() (uint16, bool) {
	if r.remaining() < 2 {
		return 0, false
	}
	v := binary.BigEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v, true
}

func (r *reader) vector(width int) ([]byte, bool) {
	var n int
	switch width {
	case 1:
		v, ok := r.byte()
		if !ok {
			return nil, false
		}
		n = int(v)
	case 2:
		v, ok := r.uint16()
		if !ok {
			return nil, false
		}
		n = int(v)
	default:
		return nil, false
	}
	start := r.pos
	if !r.skip(n) {
		return nil, false
	}
	return r.b[start:r.pos], true
}
