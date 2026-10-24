package probe

import (
	"context"
	"errors"
	"math/rand"
	"strings"
	"time"
)

type Experiment struct {
	Names   []string
	Control string
	Offsets []int // zero is plain; positive sizes request Mirage
	Rounds  int
	Delay   time.Duration
	Burst   bool
	Seed    int64
}

func (e Experiment) Plan() ([]Case, error) {
	if e.Rounds < 1 || len(e.Names) == 0 || len(e.Offsets) == 0 || e.Control == "" {
		return nil, errors.New("positive rounds, test names, offsets and a control name are required")
	}
	if e.Delay < 0 || (e.Delay == 0 && !e.Burst) {
		return nil, errors.New("zero delay requires -burst; delay cannot be negative")
	}
	for _, off := range e.Offsets {
		if off < 0 {
			return nil, errors.New("offset cannot be negative")
		}
	}
	names := []string{e.Control}
	seen := map[string]bool{e.Control: true}
	for _, name := range e.Names {
		if name == "" || strings.ContainsAny(name, "\r\n\t /:") {
			return nil, errors.New("invalid server name")
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	if strings.ContainsAny(e.Control, "\r\n\t /:") {
		return nil, errors.New("invalid control name")
	}
	rng := rand.New(rand.NewSource(e.Seed))
	var plan []Case
	for round := 1; round <= e.Rounds; round++ {
		var cases []Case
		for _, name := range names {
			role := "test"
			if name == e.Control {
				role = "control"
			}
			for _, offset := range e.Offsets {
				cases = append(cases, Case{round, role, name, offset})
			}
		}
		rng.Shuffle(len(cases), func(i, j int) { cases[i], cases[j] = cases[j], cases[i] })
		plan = append(plan, cases...)
	}
	return plan, nil
}

func Execute(ctx context.Context, options Options, plan []Case, delay time.Duration, emit func(Result) error) ([]Result, error) {
	var results []Result
	for i, experiment := range plan {
		if i > 0 && delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return results, ctx.Err()
			}
		}
		if err := ctx.Err(); err != nil {
			return results, err
		}
		result := Run(ctx, options, experiment)
		results = append(results, result)
		if err := emit(result); err != nil {
			return results, err
		}
	}
	return results, ctx.Err()
}

type Summary struct {
	Event             string `json:"event"`
	Attempts          int    `json:"attempts"`
	TCPFailures       int    `json:"tcp_failures"`
	TLSFailures       int    `json:"tls_failures"`
	HTTPFailures      int    `json:"http_failures"`
	Completed         int    `json:"completed"`
	ControlFailures   int    `json:"control_failures"`
	ComparablePairs   int    `json:"comparable_pairs"`
	MirageOnlySuccess int    `json:"mirage_only_success"`
	PlainOnlySuccess  int    `json:"plain_only_success"`
	InconclusivePairs int    `json:"inconclusive_pairs"`
}

func Summarize(results []Result) Summary {
	s := Summary{Event: "summary", Attempts: len(results)}
	badControl := map[int]bool{}
	type key struct {
		round int
		name  string
	}
	plain := map[key]Result{}
	for _, r := range results {
		if r.Status == "ok" {
			s.Completed++
		} else {
			switch r.Stage {
			case "tcp":
				s.TCPFailures++
			case "tls":
				s.TLSFailures++
			case "http":
				s.HTTPFailures++
			}
			if r.Role == "control" {
				s.ControlFailures++
				badControl[r.Round] = true
			}
		}
		if r.Offset == 0 {
			plain[key{r.Round, r.ServerName}] = r
		}
	}
	for _, r := range results {
		if r.Role != "test" || r.Offset == 0 {
			continue
		}
		p, ok := plain[key{r.Round, r.ServerName}]
		if !ok || badControl[r.Round] || p.Stage == "tcp" || r.Stage == "tcp" || !r.Fragmented {
			s.InconclusivePairs++
			continue
		}
		s.ComparablePairs++
		if p.Status != "ok" && r.Status == "ok" {
			s.MirageOnlySuccess++
		}
		if p.Status == "ok" && r.Status != "ok" {
			s.PlainOnlySuccess++
		}
	}
	return s
}
