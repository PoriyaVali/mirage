// Package probe records observations without inferring who caused a failure.
package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/PoriyaVali/mirage"
)

type Options struct {
	Address   string
	Network   string
	Timeout   time.Duration // total TCP + TLS + optional HTTP budget
	TLSConfig *tls.Config
	HTTPPath  string // empty measures TLS only; requires certificate verification
}

type Case struct {
	Round      int    `json:"round"`
	Role       string `json:"role"`
	ServerName string `json:"server_name"`
	Offset     int    `json:"requested_offset"` // zero means plain in experiment cases
}

type Result struct {
	Event   string `json:"event"`
	TimeUTC string `json:"time_utc"`
	Case
	Address       string  `json:"address"`
	Mode          string  `json:"mode"`
	AppliedOffset int     `json:"applied_offset"`
	Fragmented    bool    `json:"fragmented"`
	Stage         string  `json:"stage"`
	Status        string  `json:"status"`
	ErrorKind     string  `json:"error_kind,omitempty"`
	Error         string  `json:"error,omitempty"`
	IPFamily      string  `json:"ip_family,omitempty"`
	TCPMS         float64 `json:"tcp_ms"`
	TLSMS         float64 `json:"tls_ms"`
	HTTPMS        float64 `json:"http_ms"`
	TLSVersion    uint16  `json:"tls_version,omitempty"`
	Verified      bool    `json:"verified"`
	HTTPStatus    int     `json:"http_status,omitempty"`
	BodyBytes     int64   `json:"body_bytes,omitempty"`
	Client        string  `json:"client"`
}

func Run(ctx context.Context, options Options, experiment Case) Result {
	r := Result{Event: "probe", TimeUTC: time.Now().UTC().Format(time.RFC3339Nano),
		Case: experiment, Address: options.Address, Mode: "plain", Stage: "tcp", Status: "failed",
		Client: "go/crypto-tls " + runtime.Version()}
	if experiment.Offset > 0 {
		r.Mode = "mirage"
	}
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	started := time.Now()
	raw, err := (&net.Dialer{}).DialContext(ctx, options.Network, options.Address)
	r.TCPMS = milliseconds(time.Since(started))
	if err != nil {
		return failed(r, err)
	}
	defer raw.Close()
	if addr, ok := raw.RemoteAddr().(*net.TCPAddr); ok {
		r.IPFamily = "ipv6"
		if addr.IP.To4() != nil {
			r.IPFamily = "ipv4"
		}
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := raw.SetDeadline(deadline); err != nil {
			return failed(r, err)
		}
	}
	cfg := &tls.Config{}
	if options.TLSConfig != nil {
		cfg = options.TLSConfig.Clone()
	}
	cfg.ServerName = experiment.ServerName
	var transport net.Conn = raw
	var shaped *mirage.Conn
	if experiment.Offset > 0 {
		shaped = mirage.NewConn(raw, experiment.Offset)
		transport = shaped
	}
	c := tls.Client(transport, cfg)
	r.Stage = "tls"
	started = time.Now()
	err = c.HandshakeContext(ctx)
	r.TLSMS = milliseconds(time.Since(started))
	if shaped != nil {
		r.AppliedOffset, r.Fragmented = shaped.Fragmentation()
	}
	if err != nil {
		return failed(r, err)
	}
	r.TLSVersion = c.ConnectionState().Version
	r.Verified = !cfg.InsecureSkipVerify
	if options.HTTPPath != "" {
		r.Stage = "http"
		if !r.Verified {
			return failed(r, errors.New("HTTP measurement requires certificate verification"))
		}
		started = time.Now()
		// HandshakeContext only covers TLS; close the socket if the parent
		// context is canceled while optional HTTP I/O is blocked.
		stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
		defer stop()
		req, reqErr := http.NewRequestWithContext(ctx, "GET", "https://"+experiment.ServerName+options.HTTPPath, nil)
		if reqErr != nil {
			return failed(r, reqErr)
		}
		req.Close = true
		err = req.Write(c)
		if err == nil {
			var response *http.Response
			response, err = http.ReadResponse(bufio.NewReader(c), req)
			if err == nil {
				r.HTTPStatus = response.StatusCode
				// Read a bounded sample; success does not claim a complete large download.
				r.BodyBytes, err = io.Copy(io.Discard, io.LimitReader(response.Body, 32<<10))
				// ReadResponse's Body.Close may drain unread data; close this
				// one-shot socket first so the sample stays bounded.
				_ = raw.Close()
				_ = response.Body.Close()
				if err == nil && (r.HTTPStatus < 200 || r.HTTPStatus >= 400) {
					err = fmt.Errorf("HTTP status %d", r.HTTPStatus)
				}
			}
		}
		r.HTTPMS = milliseconds(time.Since(started))
		if err != nil {
			return failed(r, err)
		}
	}
	r.Stage, r.Status = "complete", "ok"
	return r
}

func milliseconds(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func failed(r Result, err error) Result {
	r.ErrorKind, r.Error = Classify(err), err.Error()
	return r
}

// Classify describes an error without attributing it to censorship.
func Classify(err error) string {
	var cert *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var timed net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	case errors.As(err, &cert), errors.As(err, &unknown), errors.As(err, &invalid), errors.As(err, &hostname):
		return "certificate"
	case isRefused(err):
		return "refused"
	case isReset(err):
		return "reset"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	case errors.As(err, &timed) && timed.Timeout():
		return "timeout"
	default:
		return "other"
	}
}
