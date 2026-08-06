// Package mirage splits a TLS ClientHello across two TLS records so that an
// on-path censor stops acting on the server name, while the real server still
// reassembles the handshake normally.
//
// The shape is the whole point, and it is the *size* of the first record that
// decides the outcome — not where the name sits. Measured against Iran's DPI,
// a first record of 1, 2, 4 or 5 bytes carries a censored name through, while
// 3 and everything from 6 upwards is dropped; a 64-byte first record leaves
// the name entirely in the second record and is still dropped, so the censor
// is not merely failing to find it. The safe set is reproducible and identical
// for a Go and a Chrome client hello, which makes it a property of the
// censor's parser rather than of particular byte values.
//
// Two constraints come with that:
//
//   - Both records must leave in one TCP write. The same two records sent as
//     separate segments were dropped in every measurement.
//   - A size the censor dislikes is dropped even for an allowed name, so a bad
//     choice takes the whole connection down rather than just failing to
//     evade. Splitting inside the name is one such choice, and it is what
//     several existing implementations do.
//
// Splitting at the TCP layer instead does not help at all: that censor
// reassembles the stream before matching. This has to happen at the record
// layer.
package mirage

import (
	"encoding/binary"
	"errors"
	"net"
)

const (
	recordHeaderLen = 5
	handshakeHello  = 0x01
	recordHandshake = 0x16
	extServerName   = 0x0000

	// DefaultOffset is how many bytes of the handshake message stay in the
	// small first record: the handshake header (type plus three length bytes)
	// and one byte more. That is always well ahead of the SNI extension.
	DefaultOffset = 5
)

// ErrNotClientHello is returned by Split when the buffer is not a TLS
// ClientHello record it can safely fragment.
var ErrNotClientHello = errors.New("mirage: not a splittable ClientHello")

// MeasuredSafeSizes are the first-record sizes that carried a censored server
// name through Iran's DPI in August 2026, over 680 probes from a residential
// mobile connection and a datacenter host. 3 sits between two of them and does
// not work, and nothing from 6 upwards does.
//
// This is a property of one censor at one time, not of TLS. On another network
// measure it with the miragecheck tool in this repository before trusting it;
// a size the censor dislikes is dropped even for names it allows, so a wrong
// guess costs the whole connection.
var MeasuredSafeSizes = []int{1, 2, 4, 5}

// Conn wraps a connection and fragments the first ClientHello written to it.
// Every later write passes through untouched.
type Conn struct {
	net.Conn
	offset       int
	firstWritten bool
}

// NewConn returns a Conn that fragments the first ClientHello. An offset of 0
// selects DefaultOffset.
func NewConn(conn net.Conn, offset int) *Conn {
	if offset <= 0 {
		offset = DefaultOffset
	}
	return &Conn{Conn: conn, offset: offset}
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.firstWritten {
		return c.Conn.Write(b)
	}
	c.firstWritten = true

	out, err := Split(b, c.offset)
	if err != nil {
		// Not something we can fragment - send it exactly as given.
		return c.Conn.Write(b)
	}
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
	}
	// Report the caller's length: from their point of view the whole buffer
	// was written, which is what io.Writer promises.
	return len(b), nil
}

func (c *Conn) ReaderReplaceable() bool { return true }
func (c *Conn) WriterReplaceable() bool { return c.firstWritten }
func (c *Conn) Upstream() any           { return c.Conn }

// Split rewrites a ClientHello record into two records, the first ending
// before the server name. The result is meant to be written in one call so it
// leaves as a single TCP segment.
func Split(record []byte, offset int) ([]byte, error) {
	if offset <= 0 {
		offset = DefaultOffset
	}
	if len(record) <= recordHeaderLen || record[0] != recordHandshake {
		return nil, ErrNotClientHello
	}
	handshake := record[recordHeaderLen:]
	if len(handshake) == 0 || handshake[0] != handshakeHello {
		return nil, ErrNotClientHello
	}

	sni := IndexSNI(handshake)
	if sni < 0 {
		// No server name in play, so there is nothing to gain.
		return nil, ErrNotClientHello
	}
	split := offset
	if split >= sni {
		// Never let the cut land inside the name: that layout was measured to
		// be dropped, and it is the one several other implementations pick.
		split = sni / 2
	}
	if split <= 0 || split >= len(handshake) {
		return nil, ErrNotClientHello
	}

	out := make([]byte, 0, len(record)+recordHeaderLen)
	out = appendRecord(out, record[:3], handshake[:split])
	out = appendRecord(out, record[:3], handshake[split:])
	return out, nil
}

func appendRecord(dst, headerPrefix, payload []byte) []byte {
	dst = append(dst, headerPrefix...)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(payload)))
	return append(dst, payload...)
}

// IndexSNI returns the offset of the server name inside a handshake message
// (the bytes after the record header), or -1 when there is none. It parses
// only as far as it needs to and refuses to read past the buffer.
func IndexSNI(hs []byte) int {
	r := reader{b: hs}
	if !r.skip(4) { // handshake type + 3-byte length
		return -1
	}
	if !r.skip(2 + 32) { // client_version + random
		return -1
	}
	if !r.skipVector(1) { // session_id
		return -1
	}
	if !r.skipVector(2) { // cipher_suites
		return -1
	}
	if !r.skipVector(1) { // compression_methods
		return -1
	}
	if !r.skip(2) { // extensions length
		return -1
	}
	for r.remaining() >= 4 {
		extType, ok := r.uint16()
		if !ok {
			return -1
		}
		extLen, ok := r.uint16()
		if !ok || r.remaining() < int(extLen) {
			return -1
		}
		if extType != extServerName {
			r.skip(int(extLen))
			continue
		}
		// server_name_list: list length, name type, name length, name
		if !r.skip(2) || !r.skip(1) {
			return -1
		}
		nameLen, ok := r.uint16()
		if !ok || r.remaining() < int(nameLen) || nameLen == 0 {
			return -1
		}
		return r.pos
	}
	return -1
}

// reader is a bounds-checked cursor over a byte slice.
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

func (r *reader) uint16() (uint16, bool) {
	if r.remaining() < 2 {
		return 0, false
	}
	v := binary.BigEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v, true
}

// skipVector skips a length-prefixed vector whose length field is sizeLen bytes.
func (r *reader) skipVector(sizeLen int) bool {
	switch sizeLen {
	case 1:
		if r.remaining() < 1 {
			return false
		}
		n := int(r.b[r.pos])
		r.pos++
		return r.skip(n)
	case 2:
		n, ok := r.uint16()
		if !ok {
			return false
		}
		return r.skip(int(n))
	default:
		return false
	}
}
