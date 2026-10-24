// Package tlsdial provides an opt-in authenticated crypto/tls dialer with a
// bounded last-successful-mode cache and at most one fresh TLS retry.
// Native uTLS/REALITY core integrations must implement their own dial adapter;
// importing this package does not enable a policy in an application.
package tlsdial

import (
	"container/list"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/PoriyaVali/mirage"
)

type Options struct {
	Timeout        time.Duration // total budget, default 10s
	AttemptTimeout time.Duration // per TCP+TLS attempt, default 4s
	TTL            time.Duration // successful mode lifetime, default 10m
	MaxEntries     int           // bounded LRU, default 256
	InitialMirage  bool          // false starts with ordinary TLS
	Offset         int           // zero selects mirage.DefaultOffset
	CacheScope     string        // caller's stable network/configuration identity
	DialContext    func(context.Context, string, string) (net.Conn, error)
}

type cacheKey struct {
	network, address, name, scope string
	epoch                         uint64
}
type entry struct {
	key     cacheKey
	mirage  bool
	expires time.Time
}

// Dialer is safe for concurrent use. Its cloned TLS configuration and Options
// are immutable. Call Reset on a network/configuration change and cancel old
// in-flight contexts at the application's network boundary.
type Dialer struct {
	cfg     *tls.Config
	options Options
	mu      sync.Mutex
	epoch   uint64
	cache   map[cacheKey]*list.Element
	lru     list.List
	flights map[cacheKey]chan struct{}
	now     func() time.Time
}

func New(cfg *tls.Config, options Options) (*Dialer, error) {
	if cfg == nil {
		cfg = &tls.Config{}
	}
	if cfg.InsecureSkipVerify {
		return nil, errors.New("tlsdial: certificate verification must remain enabled")
	}
	if options.Timeout < 0 || options.AttemptTimeout < 0 || options.TTL < 0 || options.MaxEntries < 0 || options.Offset < 0 {
		return nil, errors.New("tlsdial: negative options are invalid")
	}
	if options.Timeout == 0 {
		options.Timeout = 10 * time.Second
	}
	if options.AttemptTimeout == 0 {
		options.AttemptTimeout = 4 * time.Second
	}
	if options.TTL == 0 {
		options.TTL = 10 * time.Minute
	}
	if options.MaxEntries == 0 {
		options.MaxEntries = 256
	}
	if options.DialContext == nil {
		options.DialContext = (&net.Dialer{}).DialContext
	}
	copy := cfg.Clone()
	if copy.RootCAs != nil {
		copy.RootCAs = copy.RootCAs.Clone()
	}
	// Callback errors are authentication/configuration failures even if a
	// callback happens to return EOF or a net.OpError. Keep their origin.
	if verify := copy.VerifyPeerCertificate; verify != nil {
		copy.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error {
			return verificationResult(verify(raw, chains))
		}
	}
	if verify := copy.VerifyConnection; verify != nil {
		copy.VerifyConnection = func(state tls.ConnectionState) error { return verificationResult(verify(state)) }
	}
	if certificate := copy.GetClientCertificate; certificate != nil {
		copy.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, err := certificate(info)
			return cert, verificationResult(err)
		}
	}
	return &Dialer{cfg: copy, options: options, cache: map[cacheKey]*list.Element{}, flights: map[cacheKey]chan struct{}{}, now: time.Now}, nil
}

// Reset invalidates learning, including results of earlier in-flight discovery.
// It does not close connections already returned to the caller.
func (d *Dialer) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.epoch++
	d.cache = map[cacheKey]*list.Element{}
	d.lru.Init()
}

// DialContext returns a fully authenticated TLS connection. It can be assigned
// to http.Transport.DialTLSContext through a function returning net.Conn.
// Retry happens only after TLS transport EOF/reset/timeout, never after a TCP
// dial error, certificate error, TLS alert or caller cancellation. No application
// request is sent or replayed by the dialer.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (*tls.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, d.options.Timeout)
	defer cancel()
	name := d.cfg.ServerName
	if name == "" {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		name = host
	}
	d.mu.Lock()
	epoch := d.epoch
	d.mu.Unlock()
	key := cacheKey{network, address, name, d.options.CacheScope, epoch}
	if mode, ok := d.lookup(key); ok {
		return d.cached(ctx, key, mode)
	}
	release, err := d.acquire(ctx, key)
	if err != nil {
		return nil, err
	}
	if mode, ok := d.lookup(key); ok {
		release() // learned while waiting; healthy cached dials run concurrently
		return d.cached(ctx, key, mode)
	}
	defer release()
	mode := d.options.InitialMirage
	conn, actual, stage, err := d.attempt(ctx, key, mode)
	if err == nil {
		d.remember(key, actual)
		return conn, nil
	}
	if !canRetry(ctx, stage, err) {
		return nil, err
	}
	first := err
	conn, actual, _, err = d.attempt(ctx, key, !mode)
	if err == nil {
		d.remember(key, actual)
		return conn, nil
	}
	return nil, fmt.Errorf("tlsdial: both connection modes failed: %w", errors.Join(first, err))
}

func (d *Dialer) cached(ctx context.Context, key cacheKey, mode bool) (*tls.Conn, error) {
	conn, actual, stage, err := d.attempt(ctx, key, mode)
	if err == nil {
		d.remember(key, actual)
		return conn, nil
	}
	if !canRetry(ctx, stage, err) {
		return nil, err
	}
	first := err
	d.forget(key, mode)
	release, err := d.acquire(ctx, key)
	if err != nil {
		return nil, err
	}
	defer release()
	next := !mode
	if learned, ok := d.lookup(key); ok && learned != mode {
		next = learned
	}
	conn, actual, _, err = d.attempt(ctx, key, next)
	if err == nil {
		d.remember(key, actual)
		return conn, nil
	}
	return nil, fmt.Errorf("tlsdial: cached mode and retry failed: %w", errors.Join(first, err))
}

func (d *Dialer) attempt(ctx context.Context, key cacheKey, mode bool) (*tls.Conn, bool, string, error) {
	ctx, cancel := context.WithTimeout(ctx, d.options.AttemptTimeout)
	defer cancel()
	raw, err := d.options.DialContext(ctx, key.network, key.address)
	if err != nil {
		return nil, false, "tcp", err
	}
	var transport net.Conn = raw
	var shaped *mirage.Conn
	if mode {
		shaped = mirage.NewConn(raw, d.options.Offset)
		transport = shaped
	}
	cfg := d.cfg.Clone()
	cfg.ServerName = key.name
	conn := tls.Client(transport, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, false, "tls", err
	}
	actual := false
	if shaped != nil {
		_, actual = shaped.Fragmentation()
	}
	return conn, actual, "complete", nil
}

func canRetry(ctx context.Context, stage string, err error) bool {
	if ctx.Err() != nil || stage != "tls" {
		return false
	}
	var certificate *tls.CertificateVerificationError
	var callback *verificationError
	if errors.As(err, &certificate) || errors.As(err, &callback) {
		return false
	}
	var op *net.OpError
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &op) && (op.Op == "read" || op.Op == "write"))
}

type verificationError struct{ err error }

func (e *verificationError) Error() string { return e.err.Error() }
func (e *verificationError) Unwrap() error { return e.err }
func verificationResult(err error) error {
	if err == nil {
		return nil
	}
	return &verificationError{err}
}

func (d *Dialer) lookup(key cacheKey) (bool, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	element := d.cache[key]
	if element == nil {
		return false, false
	}
	value := element.Value.(entry)
	if !d.now().Before(value.expires) {
		delete(d.cache, key)
		d.lru.Remove(element)
		return false, false
	}
	d.lru.MoveToFront(element)
	return value.mirage, true
}

func (d *Dialer) remember(key cacheKey, mode bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if key.epoch != d.epoch {
		return
	}
	value := entry{key, mode, d.now().Add(d.options.TTL)}
	if element := d.cache[key]; element != nil {
		element.Value = value
		d.lru.MoveToFront(element)
		return
	}
	d.cache[key] = d.lru.PushFront(value)
	for d.lru.Len() > d.options.MaxEntries {
		last := d.lru.Back()
		delete(d.cache, last.Value.(entry).key)
		d.lru.Remove(last)
	}
}

func (d *Dialer) forget(key cacheKey, mode bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if element := d.cache[key]; element != nil && element.Value.(entry).mirage == mode {
		delete(d.cache, key)
		d.lru.Remove(element)
	}
}

// One unknown/failing mode discovery per destination. Waiters subsequently
// establish their own connections using the learned mode; sockets are not shared.
func (d *Dialer) acquire(ctx context.Context, key cacheKey) (func(), error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		d.mu.Lock()
		if done := d.flights[key]; done != nil {
			d.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		done := make(chan struct{})
		d.flights[key] = done
		d.mu.Unlock()
		return func() { d.mu.Lock(); delete(d.flights, key); close(done); d.mu.Unlock() }, nil
	}
}
