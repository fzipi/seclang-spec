package coraza

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// Observed is what one stage produced.
type Observed struct {
	Triggered    map[int]bool
	Interruption *types.Interruption
	Log          []string
	Panic        string // non-empty when the engine panicked while processing the stage
}

// BuildWAF writes the profile's auxiliary files under dir, then builds a WAF whose
// configuration root is dir and whose error log lines are appended to the returned slice.
func BuildWAF(p Profile, dir string) (coraza.WAF, *[]string, error) {
	for rel, content := range p.Files {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return nil, nil, err
		}
	}
	log := &[]string{}
	cfg := coraza.NewWAFConfig().
		WithRootFS(os.DirFS(dir)).
		WithDirectives(p.Rules).
		WithErrorCallback(func(mr types.MatchedRule) { *log = append(*log, mr.ErrorLog()) })
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		return nil, nil, err
	}
	return waf, log, nil
}

// RunStage drives one transaction through the phases the stage needs. An engine panic
// is caught and reported in Observed.Panic so one engine bug cannot abort the whole run.
func RunStage(waf coraza.WAF, log *[]string, s Stage) (o Observed) {
	defer func() {
		if r := recover(); r != nil {
			o = Observed{Triggered: map[int]bool{}, Panic: fmt.Sprint(r)}
		}
	}()
	return runStage(waf, log, s)
}

func runStage(waf coraza.WAF, log *[]string, s Stage) Observed {
	*log = nil
	tx := waf.NewTransaction()
	defer tx.Close()
	addr := s.Input.RemoteAddr
	if addr == "" {
		addr = "127.0.0.1"
	}
	method, uri, version := s.Input.Method, s.Input.URI, s.Input.Version
	if method == "" {
		method = "GET"
	}
	if uri == "" {
		uri = "/"
	}
	if version == "" {
		version = "HTTP/1.1"
	}
	tx.ProcessConnection(addr, 12345, "127.0.0.1", 80)
	tx.ProcessURI(uri, method, version)
	hasHost := false
	for k, v := range s.Input.Headers {
		if strings.EqualFold(k, "Host") {
			hasHost = true
		}
		tx.AddRequestHeader(k, v)
	}
	if !hasHost {
		tx.AddRequestHeader("Host", "localhost")
	}
	it := tx.ProcessRequestHeaders()
	if it == nil {
		if s.Input.Data != "" {
			if wit, _, _ := tx.WriteRequestBody(latin1(s.Input.Data)); wit != nil {
				it = wit
			}
		}
		if it == nil {
			it, _ = tx.ProcessRequestBody()
		}
	}
	if it == nil && s.Response != nil {
		for k, v := range s.Response.Headers {
			tx.AddResponseHeader(k, v)
		}
		status := s.Response.Status
		if status == 0 {
			status = 200
		}
		it = tx.ProcessResponseHeaders(status, "HTTP/1.1")
		if it == nil {
			if s.Response.Data != "" {
				if wit, _, _ := tx.WriteResponseBody(latin1(s.Response.Data)); wit != nil {
					it = wit
				}
			}
			if it == nil {
				it, _ = tx.ProcessResponseBody()
			}
		}
	}
	tx.ProcessLogging()
	o := Observed{Triggered: map[int]bool{}, Interruption: it}
	for _, mr := range tx.MatchedRules() {
		o.Triggered[mr.Rule().ID()] = true
	}
	o.Log = append(o.Log, *log...)
	return o
}

// CheckStage compares an observation with the expected output; the result lists every
// mismatch in words, and is empty when the stage passes.
func CheckStage(o Observed, want Output) []string {
	if o.Panic != "" {
		return []string{"engine panicked: " + o.Panic}
	}
	var msgs []string
	for _, id := range want.TriggeredRules {
		if !o.Triggered[id] {
			msgs = append(msgs, fmt.Sprintf("rule %d expected to trigger; triggered=%v", id, sortedIDs(o.Triggered)))
		}
	}
	for _, id := range want.NonTriggeredRules {
		if o.Triggered[id] {
			msgs = append(msgs, fmt.Sprintf("rule %d expected not to trigger", id))
		}
	}
	if want.NoInterruption && o.Interruption != nil {
		msgs = append(msgs, fmt.Sprintf("unexpected interruption: rule %d %s %d", o.Interruption.RuleID, o.Interruption.Action, o.Interruption.Status))
	}
	if want.Interruption != nil {
		switch {
		case o.Interruption == nil:
			msgs = append(msgs, fmt.Sprintf("expected interruption by rule %d (%s), none observed", want.Interruption.RuleID, want.Interruption.Action))
		default:
			if o.Interruption.RuleID != want.Interruption.RuleID {
				msgs = append(msgs, fmt.Sprintf("interruption by rule %d, expected %d", o.Interruption.RuleID, want.Interruption.RuleID))
			}
			if o.Interruption.Action != want.Interruption.Action {
				msgs = append(msgs, fmt.Sprintf("interruption action %q, expected %q", o.Interruption.Action, want.Interruption.Action))
			}
			if want.Interruption.Status != 0 && o.Interruption.Status != want.Interruption.Status {
				msgs = append(msgs, fmt.Sprintf("interruption status %d, expected %d", o.Interruption.Status, want.Interruption.Status))
			}
		}
	}
	logText := strings.Join(o.Log, "\n")
	if want.LogContains != "" && !strings.Contains(logText, want.LogContains) {
		msgs = append(msgs, fmt.Sprintf("log does not contain %q", want.LogContains))
	}
	if want.NoLogContains != "" && strings.Contains(logText, want.NoLogContains) {
		msgs = append(msgs, fmt.Sprintf("log contains %q", want.NoLogContains))
	}
	return msgs
}

func sortedIDs(m map[int]bool) []int {
	ids := make([]int, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}
