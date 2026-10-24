// Package cli supplies the shared, paced measurement command implementation.
package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/PoriyaVali/mirage"
	"github.com/PoriyaVali/mirage/internal/probe"
	"github.com/PoriyaVali/mirage/internal/version"
)

func Run(ctx context.Context, args []string, stdout, stderr io.Writer, tool string) int {
	flags := flag.NewFlagSet(tool, flag.ContinueOnError)
	flags.SetOutput(stderr)
	address := flags.String("addr", "1.1.1.1:443", "reachable host:port; all names use this fixed endpoint")
	network := flags.String("network", "tcp", "tcp, tcp4 or tcp6")
	timeout := flags.Duration("timeout", 8*time.Second, "total per-attempt TCP/TLS/HTTP budget")
	offset := flags.Int("offset", mirage.DefaultOffset, "first-record payload size (0 selects default in miragecheck; plain in sweep repeat)")
	control := flags.String("control", "example.com", "known supported allowed name for the same endpoint")
	trials := flags.Int("trials", 3, "interleaved rounds")
	delay := flags.Duration("delay", 15*time.Second, "pause between attempts; zero requires -burst")
	burst := flags.Bool("burst", false, "explicitly allow unpaced experiments (default delay becomes zero)")
	seed := flags.Int64("seed", 1, "reproducible shuffle seed recorded in output")
	format := flags.String("format", "text", "text, json (JSON Lines) or csv")
	verify := flags.Bool("verify", false, "verify certificates; default measures unauthenticated TLS completion only")
	ca := flags.String("ca", "", "additional PEM root certificates; requires -verify")
	httpPath := flags.String("http-path", "", "optional GET path and up to 32 KiB body sample; requires -verify")
	showVersion := flags.Bool("version", false, "print build version and exit")
	var mode, sni string
	var repeat int
	if tool == "sweep" {
		flags.StringVar(&mode, "mode", "table", "table or repeat")
		flags.StringVar(&sni, "sni", "www.instagram.com", "test server name")
		flags.IntVar(&repeat, "n", 3, "interleaved rounds in repeat mode")
	}
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version.String())
		return 0
	}
	fail := func(message string) int { fmt.Fprintln(stderr, message); return 2 }
	if _, _, err := net.SplitHostPort(*address); err != nil {
		return fail("addr must be host:port")
	}
	if *network != "tcp" && *network != "tcp4" && *network != "tcp6" {
		return fail("network must be tcp, tcp4 or tcp6")
	}
	if *timeout <= 0 || *offset < 0 || *offset > 16384 {
		return fail("timeout must be positive; offset must be between 0 and 16384")
	}
	if *format != "text" && *format != "json" && *format != "csv" {
		return fail("format must be text, json or csv")
	}
	if (*ca != "" || *httpPath != "") && !*verify {
		return fail("ca and http-path require -verify")
	}
	if *httpPath != "" && (!strings.HasPrefix(*httpPath, "/") || strings.ContainsAny(*httpPath, "\r\n")) {
		return fail("http-path must be an absolute request path")
	}
	delayExplicit := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "delay" {
			delayExplicit = true
		}
	})
	if *burst && !delayExplicit {
		*delay = 0
	}
	cfg := &tls.Config{InsecureSkipVerify: !*verify}
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			return fail(err.Error())
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return fail("ca file contains no root certificates")
		}
		cfg.RootCAs = roots
	}
	selected := *offset
	if selected == 0 {
		selected = mirage.DefaultOffset
	}
	experiment := probe.Experiment{Names: flags.Args(), Control: *control, Offsets: []int{0, selected}, Rounds: *trials, Delay: *delay, Burst: *burst, Seed: *seed}
	if tool == "sweep" {
		if flags.NArg() != 0 {
			return fail("sweep accepts names through -sni and -control")
		}
		experiment.Names = []string{sni}
		switch mode {
		case "table":
			experiment.Offsets = []int{0, 1, 2, 3, 4, 5, 8, 12, 16, 24, 32, 64}
		case "repeat":
			experiment.Rounds = repeat
			experiment.Offsets = []int{0}
			if *offset > 0 {
				experiment.Offsets = append(experiment.Offsets, *offset)
			}
		default:
			return fail("mode must be table or repeat")
		}
	}
	plan, err := experiment.Plan()
	if err != nil {
		return fail(err.Error())
	}
	output, err := probe.NewOutput(stdout, *format)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	metadata := struct {
		Event    string `json:"event"`
		Tool     string `json:"tool"`
		Build    string `json:"build"`
		Address  string `json:"address"`
		Network  string `json:"network"`
		Control  string `json:"control"`
		Seed     int64  `json:"seed"`
		Delay    string `json:"delay"`
		Burst    bool   `json:"burst"`
		Attempts int    `json:"attempts"`
	}{"experiment", tool, version.String(), *address, *network, *control, *seed, delay.String(), *burst, len(plan)}
	if err := output.Metadata(metadata); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	options := probe.Options{Address: *address, Network: *network, Timeout: *timeout, TLSConfig: cfg, HTTPPath: *httpPath}
	results, err := probe.Execute(ctx, options, plan, *delay, output.Result)
	if err != nil {
		fmt.Fprintln(stderr, err)
		if ctx.Err() != nil {
			return 130
		}
		return 1
	}
	summary := probe.Summarize(results)
	if err := output.Summary(summary); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if summary.ControlFailures > 0 || summary.TCPFailures > 0 || summary.Completed == 0 {
		return 1
	}
	return 0
}
