package probe

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

type Output struct {
	writer io.Writer
	format string
	csv    *csv.Writer
}

func NewOutput(w io.Writer, format string) (*Output, error) {
	o := &Output{writer: w, format: format}
	switch format {
	case "text", "json":
	case "csv":
		o.csv = csv.NewWriter(w)
		if err := o.row([]string{"event", "time_utc", "round", "role", "server_name", "address", "mode", "requested_offset", "applied_offset", "fragmented", "stage", "status", "error_kind", "error", "ip_family", "tcp_ms", "tls_ms", "http_ms", "tls_version", "verified", "http_status", "body_bytes", "client", "metadata_or_summary"}); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("format must be text, json or csv")
	}
	return o, nil
}

func (o *Output) Metadata(value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	switch o.format {
	case "json":
		_, err = fmt.Fprintln(o.writer, string(data))
	case "csv":
		row := make([]string, 24)
		row[0], row[23] = "experiment", string(data)
		err = o.row(row)
	default:
		_, err = fmt.Fprintf(o.writer, "experiment %s\n", data)
	}
	return err
}

func (o *Output) Result(r Result) error {
	switch o.format {
	case "json":
		return json.NewEncoder(o.writer).Encode(r)
	case "csv":
		return o.row([]string{r.Event, r.TimeUTC, strconv.Itoa(r.Round), r.Role, r.ServerName, r.Address, r.Mode, strconv.Itoa(r.Offset), strconv.Itoa(r.AppliedOffset), strconv.FormatBool(r.Fragmented), r.Stage, r.Status, r.ErrorKind, r.Error, r.IPFamily, number(r.TCPMS), number(r.TLSMS), number(r.HTTPMS), strconv.Itoa(int(r.TLSVersion)), strconv.FormatBool(r.Verified), strconv.Itoa(r.HTTPStatus), strconv.FormatInt(r.BodyBytes, 10), r.Client, ""})
	default:
		_, err := fmt.Fprintf(o.writer, "round=%d %-7s %-28s %-6s requested=%d applied=%d %-8s %-6s tcp=%.1fms tls=%.1fms verified=%t error=%q\n", r.Round, r.Role, r.ServerName, r.Mode, r.Offset, r.AppliedOffset, r.Stage, r.Status, r.TCPMS, r.TLSMS, r.Verified, r.Error)
		return err
	}
}

func (o *Output) Summary(s Summary) error {
	switch o.format {
	case "json":
		return json.NewEncoder(o.writer).Encode(s)
	case "csv":
		data, err := json.Marshal(s)
		if err != nil {
			return err
		}
		row := make([]string, 24)
		row[0], row[23] = "summary", string(data)
		return o.row(row)
	default:
		_, err := fmt.Fprintf(o.writer, "\nattempts=%d complete=%d tcp_failures=%d tls_failures=%d http_failures=%d control_failures=%d\ncomparable_pairs=%d mirage_only_success=%d plain_only_success=%d inconclusive_pairs=%d\nDifferences are observations; they do not establish censorship or its cause.\n", s.Attempts, s.Completed, s.TCPFailures, s.TLSFailures, s.HTTPFailures, s.ControlFailures, s.ComparablePairs, s.MirageOnlySuccess, s.PlainOnlySuccess, s.InconclusivePairs)
		return err
	}
}

func (o *Output) row(row []string) error {
	if err := o.csv.Write(row); err != nil {
		return err
	}
	o.csv.Flush()
	return o.csv.Error()
}

func number(f float64) string { return strconv.FormatFloat(f, 'f', 3, 64) }
