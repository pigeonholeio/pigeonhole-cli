// Package telemetry ships CLI traces (errors + timings) to otel.planesailing.io.
//
// On by default; opt out with `--no-telemetry`, PIGEONHOLE_TELEMETRY=off, or
// DO_NOT_TRACK=1. Minimal stdlib OTLP/HTTP JSON exporter — no heavy SDK deps.
// Never attaches secret content, filenames, recipients or references — only
// command, timings, outcome, errors, version/OS and (when known) the user email.
// Export failures are always silent; nothing here blocks the CLI.
package telemetry

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"
)

const (
	otelURL     = "https://otel.planesailing.io/v1/traces"
	serviceName = "pigeonhole-cli"
	// Public ingest token (noise-filter only; a distributed CLI can't hold a
	// real secret — same posture as browser bundles). Allow-listed in Alloy.
	ingestToken = "3dbae1d0b894510078a1335e3bc1b8932187caeedfd39e8393f5a518cfc82dec"
)

var (
	mu      sync.Mutex
	spans   []*Span
	traceID string
	version string
	off     bool
)

// Span is a single timed operation.
type Span struct {
	id       string
	parentID string
	name     string
	start    time.Time
	end      time.Time
	attrs    map[string]any
	errMsg   string
	status   string // "", "OK", "ERROR"
}

func randHex(n int) string { b := make([]byte, n); _, _ = rand.Read(b); return hex.EncodeToString(b) }

// Disable turns telemetry off (wired to --no-telemetry).
func Disable() { off = true }

func enabled() bool {
	if off || os.Getenv("PIGEONHOLE_TELEMETRY") == "off" || os.Getenv("DO_NOT_TRACK") == "1" {
		return false
	}
	return true
}

// Init prepares a trace for this invocation; returns a flush/shutdown fn.
func Init(v string) func() {
	version = v
	if !enabled() {
		return func() {}
	}
	traceID = randHex(16)
	return flush
}

var root *Span

// StartRoot begins the per-invocation root span (stored for child linkage).
func StartRoot(name string) *Span { root = Start(name, nil); return root }

// Root returns the current invocation's root span (nil if none).
func Root() *Span { return root }

// Start begins a span. parent may be nil (root).
func Start(name string, parent *Span) *Span {
	s := &Span{id: randHex(8), name: name, start: time.Now(), attrs: map[string]any{}}
	if parent != nil {
		s.parentID = parent.id
	}
	return s
}

func (s *Span) SetAttr(k string, v any) {
	if s == nil {
		return
	}
	s.attrs[k] = v
}

// SetName renames the span (e.g. to the resolved command, for easy querying).
func (s *Span) SetName(name string) {
	if s == nil {
		return
	}
	s.name = name
}

func (s *Span) Fail(err error) {
	if s == nil || err == nil {
		return
	}
	s.status = "ERROR"
	s.errMsg = err.Error()
}

func (s *Span) End() {
	if s == nil {
		return
	}
	s.end = time.Now()
	if s.status == "" {
		s.status = "OK"
	}
	mu.Lock()
	spans = append(spans, s)
	mu.Unlock()
}

func flush() {
	mu.Lock()
	collected := spans
	spans = nil
	mu.Unlock()
	if !enabled() || len(collected) == 0 {
		return
	}
	payload := buildOTLP(collected)
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", otelURL, bytes.NewReader(b))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+ingestToken)
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

func buildOTLP(collected []*Span) map[string]any {
	attrKV := func(m map[string]any) []map[string]any {
		out := []map[string]any{}
		for k, v := range m {
			out = append(out, map[string]any{"key": k, "value": otlpValue(v)})
		}
		return out
	}
	otlpSpans := make([]map[string]any, 0, len(collected))
	for _, s := range collected {
		span := map[string]any{
			"traceId":           traceID,
			"spanId":            s.id,
			"name":              s.name,
			"kind":              1,
			"startTimeUnixNano": fmt.Sprintf("%d", s.start.UnixNano()),
			"endTimeUnixNano":   fmt.Sprintf("%d", s.end.UnixNano()),
			"attributes":        attrKV(s.attrs),
			"status":            map[string]any{"code": statusCode(s.status)},
		}
		if s.parentID != "" {
			span["parentSpanId"] = s.parentID
		}
		if s.errMsg != "" {
			span["status"] = map[string]any{"code": 2, "message": s.errMsg}
			span["events"] = []map[string]any{{
				"timeUnixNano": fmt.Sprintf("%d", s.end.UnixNano()),
				"name":         "exception",
				"attributes": []map[string]any{
					{"key": "exception.message", "value": map[string]any{"stringValue": s.errMsg}},
					{"key": "exception.type", "value": map[string]any{"stringValue": "error"}},
				},
			}}
		}
		otlpSpans = append(otlpSpans, span)
	}
	return map[string]any{
		"resourceSpans": []map[string]any{{
			"resource": map[string]any{"attributes": []map[string]any{
				{"key": "service.name", "value": map[string]any{"stringValue": serviceName}},
				{"key": "service.version", "value": map[string]any{"stringValue": version}},
				{"key": "os.type", "value": map[string]any{"stringValue": runtime.GOOS}},
				{"key": "host.arch", "value": map[string]any{"stringValue": runtime.GOARCH}},
			}},
			"scopeSpans": []map[string]any{{"spans": otlpSpans}},
		}},
	}
}

func statusCode(s string) int {
	if s == "ERROR" {
		return 2
	}
	return 1
}

func otlpValue(v any) map[string]any {
	switch t := v.(type) {
	case string:
		return map[string]any{"stringValue": t}
	case int:
		return map[string]any{"intValue": fmt.Sprintf("%d", t)}
	case int64:
		return map[string]any{"intValue": fmt.Sprintf("%d", t)}
	case float64:
		return map[string]any{"doubleValue": t}
	case bool:
		return map[string]any{"boolValue": t}
	default:
		return map[string]any{"stringValue": fmt.Sprintf("%v", t)}
	}
}
