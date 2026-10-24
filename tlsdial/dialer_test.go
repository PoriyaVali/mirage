package tlsdial

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type shapeListener struct {
	net.Listener
	allow func(bool) bool
	seen  chan bool
}

func (l *shapeListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &shapeConn{Conn: conn, allow: l.allow, seen: l.seen}, nil
}

type shapeConn struct {
	net.Conn
	allow  func(bool) bool
	seen   chan bool
	once   sync.Once
	reader io.Reader
	err    error
}

func (c *shapeConn) Read(b []byte) (int, error) {
	c.once.Do(func() {
		header := make([]byte, 5)
		if _, c.err = io.ReadFull(c.Conn, header); c.err != nil {
			return
		}
		fragmented := binary.BigEndian.Uint16(header[3:5]) == 5
		c.seen <- fragmented
		if !c.allow(fragmented) {
			_ = c.Conn.Close()
			c.err = io.EOF
			return
		}
		c.reader = io.MultiReader(bytes.NewReader(header), c.Conn)
	})
	if c.err != nil {
		return 0, c.err
	}
	return c.reader.Read(b)
}

func shapeServer(t *testing.T, allow func(bool) bool, serverConfig ...*tls.Config) (*httptest.Server, *tls.Config, chan bool) {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "authenticated data") }))
	seen := make(chan bool, 100)
	server.Listener = &shapeListener{Listener: server.Listener, allow: allow, seen: seen}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	if len(serverConfig) > 0 {
		server.TLS = serverConfig[0]
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return server, &tls.Config{RootCAs: roots, ServerName: "example.com"}, seen
}

func TestLearnsBothDirections(t *testing.T) {
	for _, want := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "mirage"}[want], func(t *testing.T) {
			server, cfg, seen := shapeServer(t, func(mode bool) bool { return mode == want })
			d, err := New(cfg, Options{InitialMirage: !want})
			if err != nil {
				t.Fatal(err)
			}
			conn, err := d.DialContext(context.Background(), "tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			if len(conn.ConnectionState().VerifiedChains) == 0 {
				t.Fatal("connection not authenticated")
			}
			_ = conn.Close()
			if len(seen) != 2 || <-seen != !want || <-seen != want {
				t.Fatal("expected exactly two opposite modes")
			}
			conn, err = d.DialContext(context.Background(), "tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
			if len(seen) != 1 || <-seen != want {
				t.Fatal("winner was not remembered")
			}
		})
	}
}

func TestNoRetryAfterTCPOrCertificateError(t *testing.T) {
	var calls atomic.Int32
	d, err := New(nil, Options{DialContext: func(context.Context, string, string) (net.Conn, error) { calls.Add(1); return nil, io.EOF }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.DialContext(context.Background(), "tcp", "127.0.0.1:1"); err == nil || calls.Load() != 1 {
		t.Fatalf("TCP retry count=%d err=%v", calls.Load(), err)
	}
	server, _, seen := shapeServer(t, func(bool) bool { return true })
	d, err = New(&tls.Config{ServerName: "example.com", RootCAs: x509.NewCertPool()}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.DialContext(context.Background(), "tcp", server.Listener.Addr().String()); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	if len(seen) != 1 {
		t.Fatal("certificate failure triggered retry")
	}
	if _, err := New(&tls.Config{InsecureSkipVerify: true}, Options{}); err == nil {
		t.Fatal("insecure config accepted")
	}
}

func TestAtMostTwoAttempts(t *testing.T) {
	server, cfg, seen := shapeServer(t, func(bool) bool { return false })
	d, err := New(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.DialContext(context.Background(), "tcp", server.Listener.Addr().String()); err == nil {
		t.Fatal("failed modes reported success")
	}
	if len(seen) != 2 {
		t.Fatalf("attempts=%d", len(seen))
	}
}

func TestNoRetryAfterProtocolAlertOrVerificationCallback(t *testing.T) {
	t.Run("protocol_alert", func(t *testing.T) {
		server, cfg, seen := shapeServer(t, func(bool) bool { return true }, &tls.Config{MinVersion: tls.VersionTLS13})
		cfg.MaxVersion = tls.VersionTLS12
		d, err := New(cfg, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.DialContext(context.Background(), "tcp", server.Listener.Addr().String()); err == nil {
			t.Fatal("protocol mismatch accepted")
		}
		if len(seen) != 1 {
			t.Fatalf("protocol alert triggered %d attempts", len(seen))
		}
	})
	t.Run("verification_callback", func(t *testing.T) {
		server, cfg, seen := shapeServer(t, func(bool) bool { return true })
		cfg.VerifyConnection = func(tls.ConnectionState) error { return io.EOF }
		d, err := New(cfg, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.DialContext(context.Background(), "tcp", server.Listener.Addr().String()); !errors.Is(err, io.EOF) {
			t.Fatalf("callback error=%v", err)
		}
		if len(seen) != 1 {
			t.Fatalf("verification callback triggered %d attempts", len(seen))
		}
	})
	t.Run("peer_certificate_callback", func(t *testing.T) {
		server, cfg, seen := shapeServer(t, func(bool) bool { return true })
		cfg.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error { return io.EOF }
		d, err := New(cfg, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.DialContext(context.Background(), "tcp", server.Listener.Addr().String()); !errors.Is(err, io.EOF) {
			t.Fatalf("callback error=%v", err)
		}
		if len(seen) != 1 {
			t.Fatalf("peer verification triggered %d attempts", len(seen))
		}
	})
	t.Run("client_certificate_callback", func(t *testing.T) {
		server, cfg, seen := shapeServer(t, func(bool) bool { return true }, &tls.Config{ClientAuth: tls.RequestClientCert})
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return nil, io.EOF }
		d, err := New(cfg, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.DialContext(context.Background(), "tcp", server.Listener.Addr().String()); !errors.Is(err, io.EOF) {
			t.Fatalf("callback error=%v", err)
		}
		if len(seen) != 1 {
			t.Fatalf("client certificate callback triggered %d attempts", len(seen))
		}
	})
}

func TestReturnedConnectionCarriesDataAfterDialContextEnds(t *testing.T) {
	server, cfg, seen := shapeServer(t, func(mode bool) bool { return mode })
	d, err := New(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := d.DialContext(ctx, "tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel() // setup-only cancellation must not kill the returned connection
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest("GET", "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Close = true
	if err := request.Write(conn); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(body) != "authenticated data" || response.StatusCode != 200 {
		t.Fatalf("response=%s err=%v", body, err)
	}
	if len(seen) != 2 {
		t.Fatal("application exchange created another connection")
	}
}

func TestResetTTLAndBoundedCache(t *testing.T) {
	var requireMirage atomic.Bool
	requireMirage.Store(true)
	server, cfg, seen := shapeServer(t, func(mode bool) bool { return mode == requireMirage.Load() })
	d, err := New(cfg, Options{MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now()
	d.now = func() time.Time { return clock }
	dial := func(network string) {
		t.Helper()
		conn, err := d.DialContext(context.Background(), network, server.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
	dial("tcp")
	if len(seen) != 2 {
		t.Fatal("did not discover Mirage")
	}
	for len(seen) > 0 {
		<-seen
	}
	requireMirage.Store(false)
	d.Reset()
	dial("tcp")
	if len(seen) != 1 || <-seen {
		t.Fatal("reset reused stale Mirage mode")
	}
	dial("tcp4")
	if len(d.cache) != 1 || d.lru.Len() != 1 {
		t.Fatal("cache exceeded bound")
	}
	for len(seen) > 0 {
		<-seen
	}
	clock = clock.Add(d.options.TTL + time.Second)
	requireMirage.Store(true)
	dial("tcp4")
	if len(seen) != 2 || <-seen || !<-seen {
		t.Fatal("expired cache was reused")
	}
}

func TestConcurrentDiscoveryDoesNotRepeatFailedMode(t *testing.T) {
	server, cfg, seen := shapeServer(t, func(mode bool) bool { return mode })
	d, err := New(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			conn, err := d.DialContext(context.Background(), "tcp", server.Listener.Addr().String())
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
		}()
	}
	close(start)
	wg.Wait()
	plain := 0
	for len(seen) > 0 {
		if !<-seen {
			plain++
		}
	}
	if plain != 1 {
		t.Fatalf("discovery repeated failed plain mode %d times", plain)
	}
}

func TestBudgetAndCanceledDiscoveryWaiter(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 4)
	release := make(chan struct{})
	defer close(release)
	var sockets sync.WaitGroup
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			sockets.Add(1)
			accepted <- struct{}{}
			go func() { defer sockets.Done(); defer conn.Close(); <-release }()
		}
	}()
	d, err := New(&tls.Config{ServerName: "example.com"}, Options{Timeout: 150 * time.Millisecond, AttemptTimeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	done := make(chan error, 1)
	go func() { _, err := d.DialContext(context.Background(), "tcp", listener.Addr().String()); done <- err }()
	<-accepted
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.DialContext(ctx, "tcp", listener.Addr().String()); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter=%v", err)
	}
	if err := <-done; err == nil {
		t.Fatal("stalled TLS reported success")
	}
	if time.Since(started) > time.Second {
		t.Fatal("total budget exceeded")
	}
	if len(accepted) > 1 {
		t.Fatal("more than two total attempts")
	}
}
