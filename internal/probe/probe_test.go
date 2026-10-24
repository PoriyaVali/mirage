package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVerifiedTLSAndHTTP(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "verified sample") }))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	opts := Options{Address: server.Listener.Addr().String(), Network: "tcp", Timeout: time.Second, TLSConfig: &tls.Config{RootCAs: roots}, HTTPPath: "/"}
	result := Run(context.Background(), opts, Case{1, "test", "example.com", 5})
	if result.Status != "ok" || !result.Verified || !result.Fragmented || result.AppliedOffset != 5 || result.BodyBytes != 15 || result.HTTPStatus != 200 {
		t.Fatalf("result: %+v", result)
	}
	opts.TLSConfig = &tls.Config{RootCAs: x509.NewCertPool()}
	result = Run(context.Background(), opts, Case{1, "test", "example.com", 5})
	if result.Stage != "tls" || result.ErrorKind != "certificate" || result.Verified {
		t.Fatalf("untrusted result: %+v", result)
	}
}

func TestTCPRefusalIsNotTLSFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	r := Run(context.Background(), Options{Address: addr, Network: "tcp", Timeout: time.Second}, Case{1, "test", "example.com", 5})
	if r.Stage != "tcp" || r.Status != "failed" || r.TLSMS != 0 || r.Fragmented {
		t.Fatalf("result: %+v", r)
	}
	if r.ErrorKind != "refused" {
		t.Fatalf("kind=%s error=%s", r.ErrorKind, r.Error)
	}
}

func TestTLSBudgetAndCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	release := make(chan struct{})
	defer close(release)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		<-release
	}()
	started := time.Now()
	r := Run(context.Background(), Options{Address: listener.Addr().String(), Network: "tcp", Timeout: 50 * time.Millisecond, TLSConfig: &tls.Config{InsecureSkipVerify: true}}, Case{1, "test", "example.com", 5})
	if r.Stage != "tls" || r.ErrorKind != "timeout" || time.Since(started) > time.Second {
		t.Fatalf("result: %+v", r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = Run(ctx, Options{Address: listener.Addr().String(), Network: "tcp", Timeout: time.Second}, Case{})
	if r.ErrorKind != "canceled" {
		t.Fatalf("cancellation: %+v", r)
	}
}

func TestExperimentControlsAndSummary(t *testing.T) {
	experiment := Experiment{Names: []string{"test.example"}, Control: "control.example", Offsets: []int{0, 5}, Rounds: 3, Delay: time.Second, Seed: 42}
	plan, err := experiment.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 12 {
		t.Fatalf("plan size %d", len(plan))
	}
	counts := map[int]map[string]int{}
	for _, c := range plan {
		if counts[c.Round] == nil {
			counts[c.Round] = map[string]int{}
		}
		counts[c.Round][c.Role]++
	}
	for round, roles := range counts {
		if roles["test"] != 2 || roles["control"] != 2 {
			t.Fatalf("round %d: %v", round, roles)
		}
	}
	results := []Result{
		{Case: Case{1, "control", "control.example", 0}, Stage: "complete", Status: "ok"},
		{Case: Case{1, "control", "control.example", 5}, Stage: "complete", Status: "ok", Fragmented: true},
		{Case: Case{1, "test", "test.example", 0}, Stage: "tcp", Status: "failed"},
		{Case: Case{1, "test", "test.example", 5}, Stage: "complete", Status: "ok", Fragmented: true},
	}
	if s := Summarize(results); s.TCPFailures != 1 || s.ComparablePairs != 0 || s.InconclusivePairs != 1 || s.MirageOnlySuccess != 0 {
		t.Fatalf("TCP counted as shape difference: %+v", s)
	}
	results[2].Stage = "tls"
	if s := Summarize(results); s.ComparablePairs != 1 || s.MirageOnlySuccess != 1 {
		t.Fatalf("TLS comparison: %+v", s)
	}
	results[0].Status, results[0].Stage = "failed", "tls"
	if s := Summarize(results); s.ComparablePairs != 0 || s.InconclusivePairs != 1 {
		t.Fatalf("ignored failed control: %+v", s)
	}
	experiment.Delay = 0
	if _, err := experiment.Plan(); err == nil {
		t.Fatal("unpaced measurement accepted without burst")
	}
}

func TestOutputFormatsAndWriteErrors(t *testing.T) {
	r := Result{Event: "probe", Case: Case{1, "test", "example.com", 5}, Stage: "tls", Status: "failed", Error: "quoted,\"error\"\nline"}
	for _, format := range []string{"text", "json", "csv"} {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			out, err := NewOutput(&buf, format)
			if err != nil {
				t.Fatal(err)
			}
			if err := out.Metadata(map[string]string{"event": "experiment"}); err != nil {
				t.Fatal(err)
			}
			if err := out.Result(r); err != nil {
				t.Fatal(err)
			}
			if err := out.Summary(Summarize([]Result{r})); err != nil {
				t.Fatal(err)
			}
			switch format {
			case "json":
				decoder := json.NewDecoder(&buf)
				count := 0
				for {
					var v map[string]any
					err := decoder.Decode(&v)
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					count++
				}
				if count != 3 {
					t.Fatalf("records %d", count)
				}
			case "csv":
				rows, err := csv.NewReader(&buf).ReadAll()
				if err != nil {
					t.Fatal(err)
				}
				if len(rows) != 4 || rows[2][13] != r.Error {
					t.Fatalf("rows %v", rows)
				}
			default:
				if strings.Contains(buf.String(), "blocked") {
					t.Fatal("attributed failure")
				}
			}
		})
	}
	out, err := NewOutput(rejectWriter{}, "json")
	if err != nil {
		t.Fatal(err)
	}
	if err := out.Result(r); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write error %v", err)
	}
}

type rejectWriter struct{}

func (rejectWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
