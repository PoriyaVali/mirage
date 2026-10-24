package cli

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRefusedTCPCommands(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	for _, tool := range []string{"miragecheck", "sweep"} {
		for _, format := range []string{"text", "json", "csv"} {
			args := []string{"-addr", addr, "-burst", "-trials", "1", "-format", format}
			if tool == "sweep" {
				args = append(args, "-mode", "repeat", "-n", "1", "-sni", "test.example")
			} else {
				args = append(args, "test.example")
			}
			var out, stderr bytes.Buffer
			if code := Run(context.Background(), args, &out, &stderr, tool); code != 1 {
				t.Fatalf("%s/%s code=%d stderr=%s", tool, format, code, stderr.String())
			}
			if strings.Contains(out.String(), "blocked") || strings.Contains(out.String(), "censor reacts") {
				t.Fatalf("false attribution: %s", out.String())
			}
			if !strings.Contains(out.String(), "tcp_failures") {
				t.Fatal("missing staged summary")
			}
		}
	}
}

func TestCLIValidationAndVersion(t *testing.T) {
	for _, args := range [][]string{
		{"-delay", "0", "example.com"}, {"-trials", "0", "example.com"}, {"-format", "bad", "example.com"},
		{"-http-path", "/", "example.com"}, {"-offset", "-1", "example.com"}, {"-control", "bad/name", "example.com"},
	} {
		var out, stderr bytes.Buffer
		if code := Run(context.Background(), args, &out, &stderr, "miragecheck"); code != 2 {
			t.Fatalf("args=%v code=%d", args, code)
		}
		if out.Len() != 0 {
			t.Fatal("invalid arguments started measurement")
		}
	}
	var out bytes.Buffer
	if code := Run(context.Background(), []string{"-version"}, &out, io.Discard, "miragecheck"); code != 0 || !strings.Contains(out.String(), "commit=") {
		t.Fatalf("version: %s code=%d", out.String(), code)
	}
}

func TestVerifiedHTTPCommand(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "hello") }))
	defer server.Close()
	cert := server.Certificate()
	if _, err := x509.ParseCertificate(cert.Raw); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-addr", server.Listener.Addr().String(), "-burst", "-trials", "1", "-format", "json", "-verify", "-ca", path, "-http-path", "/", "example.com"}
	var out, stderr bytes.Buffer
	if code := Run(context.Background(), args, &out, &stderr, "miragecheck"); code != 0 {
		t.Fatalf("code=%d stderr=%s out=%s", code, stderr.String(), out.String())
	}
	if !strings.Contains(out.String(), `"verified":true`) || !strings.Contains(out.String(), `"body_bytes":5`) {
		t.Fatalf("missing authenticated transfer: %s", out.String())
	}
}
