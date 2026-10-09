// Command differential drives Coraza with seeded random requests against every Core
// engine profile's ruleset and writes what Coraza did, in the engine-profile JSON shape
// that formal/EvalMain.lean reads (the same shape as tools/engine_rules.py), so that
// `lake exe seclang-eval` can check that the Lean model agrees with the engine on inputs
// no hand-written profile anticipated.
//
//	cd adapters/coraza && go run ./cmd/differential -n 30 -seed 1 > ../../formal/.lake/differential.json
//	cd formal && lake exe seclang-eval .lake/differential.json
//
// Skipped: profiles with `requires:` (Extended), with a Coraza row in compat/known-gaps.md
// (the engine deviates from the specification there by record), with expect_error or log
// assertions, and any request on which the engine panicked.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	adapter "github.com/OWASP/seclang-spec/adapters/coraza"
)

type profileOut struct {
	Path        string            `json:"path"`
	Rules       string            `json:"rules"`
	Files       map[string]string `json:"files"`
	ExpectError bool              `json:"expect_error"`
	Tests       []testOut         `json:"tests"`
}
type testOut struct {
	Title  string     `json:"test_title"`
	Stages []stageOut `json:"stages"`
}
type stageOut struct {
	Stage stageBody `json:"stage"`
}
type stageBody struct {
	Input    inputOut    `json:"input"`
	Response responseOut `json:"response"`
	Output   outputOut   `json:"output"`
}
type inputOut struct {
	Method  string            `json:"method"`
	URI     string            `json:"uri"`
	Headers map[string]string `json:"headers"`
	Data    string            `json:"data,omitempty"`
}
type responseOut struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Data    string            `json:"data"`
}
type outputOut struct {
	TriggeredRules    []int                   `json:"triggered_rules"`
	NonTriggeredRules []int                   `json:"non_triggered_rules"`
	Interruption      *map[string]interface{} `json:"interruption,omitempty"`
	NoInterruption    bool                    `json:"no_interruption,omitempty"`
}

var (
	reID             = regexp.MustCompile(`\bid:(\d+)`)
	reArg            = regexp.MustCompile(`ARGS(?:_GET|_POST)?:([A-Za-z0-9_.-]+)`)
	reHeader         = regexp.MustCompile(`REQUEST_HEADERS:([A-Za-z0-9_-]+)`)
	reCookie         = regexp.MustCompile(`REQUEST_COOKIES:([A-Za-z0-9_-]+)`)
	reParam          = regexp.MustCompile(`"!?@[A-Za-z]+ ([^"]{1,40})"`)
	reNumericOp      = regexp.MustCompile(`@(eq|ge|gt|le|lt)\b`)
	reBodyLimit      = regexp.MustCompile(`SecRequestBodyLimit (\d+)`)
	reDigitsThenText = regexp.MustCompile(`^[+-]?\d+[^\d]`)
)

var generic = []string{"", "1", "2", "0", "x", "abc", "foo bar", "FOO", "1.0", "-1", "a=b", "a,b", "a;b",
	"<script>", "../../etc/passwd", "' OR 1=1", "%27", "%00", "+", "&", "%2F", "/a/./b/../c", "ÿ",
	"user-42", "user-x", "hello world", "secret", "forbidden", "10.1.2.3", "203.0.113.9", "a b c", "  ", "AbC"}

func uniq(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func captures(re *regexp.Regexp, text string) []string {
	var out []string
	for _, m := range re.FindAllStringSubmatch(text, -1) {
		out = append(out, m[1])
	}
	return uniq(out)
}

func pick(r *rand.Rand, xs []string) string { return xs[r.Intn(len(xs))] }

// mutate returns the value or a near miss of it, so matching and non-matching inputs both appear.
func mutate(r *rand.Rand, v string) string {
	switch r.Intn(8) {
	case 0:
		return strings.ToUpper(v)
	case 1:
		return v + "x"
	case 2:
		return "x" + v
	case 3:
		return url.QueryEscape(v)
	case 4:
		return v + v
	default:
		return v
	}
}

func main() {
	n := flag.Int("n", 30, "requests per profile")
	seed := flag.Int64("seed", 1, "random seed")
	flag.Parse()
	root := adapter.RepoRoot()
	profiles, err := adapter.LoadProfiles(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	gaps, err := adapter.LoadGaps(filepath.Join(root, "compat", "known-gaps.md"), "coraza")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var out []profileOut
	skipped := 0
	for pi, p := range profiles {
		if len(p.Requires) > 0 || gaps[p.Path] != "" || unsuited(p) {
			skipped++
			continue
		}
		dir, _ := os.MkdirTemp("", "diff")
		waf, log, err := adapter.BuildWAF(p, dir)
		if err != nil {
			os.RemoveAll(dir)
			skipped++
			continue
		}
		r := rand.New(rand.NewSource(*seed*1000003 + int64(pi)))
		ids := idsOf(p.Rules)
		args := append(captures(reArg, p.Rules), "a", "b", "q")
		headers := append(captures(reHeader, p.Rules), "X-Test")
		cookies := captures(reCookie, p.Rules)
		values := append(captures(reParam, p.Rules), generic...)
		if reNumericOp.MatchString(p.Rules) {
			// 06#eq: leading digits followed by text convert differently per engine and are
			// unspecified, so a numeric profile never sees such a value.
			var kept []string
			for _, v := range values {
				if !reDigitsThenText.MatchString(v) {
					kept = append(kept, v)
				}
			}
			values = kept
		}
		wantsBody := strings.Contains(p.Rules, "ARGS_POST") || strings.Contains(p.Rules, "REQUEST_BODY") ||
			strings.Contains(p.Rules, "REQBODY") || strings.Contains(p.Rules, "FILES") || strings.Contains(p.Rules, "MULTIPART") ||
			regexp.MustCompile(`\bARGS\b`).MatchString(p.Rules)
		// a body of exactly SecRequestBodyLimit bytes is a recorded Coraza gap (>=); never generate one
		avoid := map[int]bool{}
		for _, m := range reBodyLimit.FindAllStringSubmatch(p.Rules, -1) {
			n, _ := strconv.Atoi(m[1])
			avoid[n] = true
		}
		po := profileOut{Path: p.Path + "#differential", Rules: p.Rules, Files: p.Files}
		if po.Files == nil {
			po.Files = map[string]string{}
		}
		for k := 0; k < *n; k++ {
			in := genInput(r, args, headers, cookies, values, wantsBody && r.Intn(3) > 0, reNumericOp.MatchString(p.Rules))
			if avoid[len(in.Data)] {
				in.Data += "&z=1"
			}
			stage := adapter.Stage{Input: adapter.Input{Method: in.Method, URI: in.URI, Headers: in.Headers, Data: in.Data},
				Response: &adapter.Response{Status: 200, Headers: map[string]string{"Content-Type": "text/plain"}, Data: "ok"}}
			obs := adapter.RunStage(waf, log, stage)
			if obs.Panic != "" {
				continue
			}
			o := outputOut{}
			for _, id := range ids {
				if obs.Triggered[id] {
					o.TriggeredRules = append(o.TriggeredRules, id)
				} else {
					o.NonTriggeredRules = append(o.NonTriggeredRules, id)
				}
			}
			if obs.Interruption != nil {
				m := map[string]interface{}{"rule_id": obs.Interruption.RuleID, "action": obs.Interruption.Action}
				o.Interruption = &m
			} else {
				o.NoInterruption = true
			}
			po.Tests = append(po.Tests, testOut{Title: fmt.Sprintf("gen %d", k), Stages: []stageOut{{Stage: stageBody{
				Input: in, Response: responseOut{Status: 200, Headers: map[string]string{"Content-Type": "text/plain"}, Data: "ok"}, Output: o}}}})
		}
		os.RemoveAll(dir)
		out = append(out, po)
	}
	fmt.Fprintf(os.Stderr, "%d profiles generated, %d skipped\n", len(out), skipped)
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		os.Exit(2)
	}
}

// unsuited: expect_error profiles and log assertions, which the model does not carry.
func unsuited(p adapter.Profile) bool {
	for _, t := range p.Tests {
		for _, s := range t.Stages {
			if s.Stage.Output.ExpectError || s.Stage.Output.LogContains != "" || s.Stage.Output.NoLogContains != "" {
				return true
			}
		}
	}
	return false
}

func idsOf(rules string) []int {
	var ids []int
	for _, m := range reID.FindAllStringSubmatch(rules, -1) {
		id, _ := strconv.Atoi(m[1])
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

func genInput(r *rand.Rand, args, headers, cookies, values []string, body bool, numeric bool) inputOut {
	in := inputOut{Method: "GET", Headers: map[string]string{}}
	value := func() string {
		for {
			v := mutate(r, pick(r, values))
			if !numeric || !reDigitsThenText.MatchString(v) {
				return v
			}
		}
	}
	var q []string
	for i := r.Intn(4); i > 0; i-- {
		q = append(q, url.QueryEscape(pick(r, args))+"="+url.QueryEscape(value()))
	}
	path := "/"
	if r.Intn(3) == 0 {
		path = "/" + pick(r, []string{"index.php", "a/b", "dir/file.php", "x%20y", ".."})
	}
	in.URI = path
	if len(q) > 0 {
		in.URI += "?" + strings.Join(q, "&")
	}
	for i := r.Intn(3); i > 0; i-- {
		in.Headers[pick(r, headers)] = value()
	}
	if len(cookies) > 0 && r.Intn(2) == 0 {
		in.Headers["Cookie"] = pick(r, cookies) + "=" + value()
	}
	if body {
		in.Method = "POST"
		var b []string
		for i := 1 + r.Intn(3); i > 0; i-- {
			b = append(b, url.QueryEscape(pick(r, args))+"="+url.QueryEscape(value()))
		}
		in.Headers["Content-Type"] = "application/x-www-form-urlencoded"
		in.Data = strings.Join(b, "&")
	}
	return in
}
