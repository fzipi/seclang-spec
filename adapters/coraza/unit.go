package coraza

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// UnitResult is what one unit case produced.
type UnitResult struct {
	Matched bool     // operators: rule 2 matched
	Output  string   // transformations: the transformed value, as a byte string
	Groups  []string // TX:0..9 when the case has re_groups
}

// unitRules wraps a unit case in a rule set: the input arrives as a raw request body,
// exposed through REQUEST_BODY by forceRequestBodyVariable (ADR-0022).
func unitRules(c UnitCase) string {
	var b strings.Builder
	b.WriteString("SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyLimit 1048576\n")
	b.WriteString("SecRule REQUEST_HEADERS:X-Seclang-Unit \"@unconditionalMatch\" \"id:1,phase:1,pass,nolog,ctl:forceRequestBodyVariable=On\"\n")
	switch c.Type {
	case "op":
		op := "@" + c.Name
		if c.HasParam {
			op += " " + escapeParam(c.Param)
		}
		capture := ""
		if len(c.ReGroups) > 0 {
			capture = ",capture"
		}
		fmt.Fprintf(&b, "SecRule REQUEST_BODY \"%s\" \"id:2,phase:2,pass,nolog%s\"\n", op, capture)
	default:
		fmt.Fprintf(&b, "SecRule REQUEST_BODY \"@unconditionalMatch\" \"id:2,phase:2,pass,nolog,t:%s\"\n", c.Name)
	}
	return b.String()
}

// wafFor builds (and the caller caches) the WAF for a case's rule set.
func wafFor(c UnitCase, dir string) (coraza.WAF, error) {
	waf, _, err := BuildWAF(Profile{Rules: unitRules(c)}, dir)
	return waf, err
}

// RunUnit evaluates one unit case against a freshly built WAF.
func RunUnit(c UnitCase, dir string) (UnitResult, error) {
	waf, err := wafFor(c, dir)
	if err != nil {
		return UnitResult{}, err
	}
	return runUnitWith(waf, c)
}

func runUnitWith(waf coraza.WAF, c UnitCase) (res UnitResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("engine panicked: %v", r)
		}
	}()
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ProcessConnection("127.0.0.1", 12345, "127.0.0.1", 80)
	tx.ProcessURI("/", "POST", "HTTP/1.1")
	tx.AddRequestHeader("Host", "localhost")
	tx.AddRequestHeader("Content-Type", "application/octet-stream")
	tx.AddRequestHeader("X-Seclang-Unit", "1")
	tx.ProcessRequestHeaders()
	if _, _, err := tx.WriteRequestBody(latin1(c.Input)); err != nil {
		return res, err
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		return res, err
	}
	for _, mr := range tx.MatchedRules() {
		if mr.Rule().ID() != 2 {
			continue
		}
		res.Matched = true
		if md := mr.MatchedDatas(); len(md) > 0 {
			res.Output = byteString([]byte(md[0].Value()))
		}
	}
	if len(c.ReGroups) > 0 {
		if st, ok := tx.(plugintypes.TransactionState); ok {
			txc := st.Variables().TX()
			for i := 0; i <= 9; i++ {
				v := txc.Get(strconv.Itoa(i))
				if len(v) == 0 {
					break
				}
				res.Groups = append(res.Groups, byteString([]byte(v[0])))
			}
		}
	}
	tx.ProcessLogging()
	return res, nil
}

// CheckUnit compares a result with the case; empty when it passes.
func CheckUnit(c UnitCase, r UnitResult) []string {
	var msgs []string
	switch c.Type {
	case "op":
		if r.Matched != (c.Ret == 1) {
			msgs = append(msgs, fmt.Sprintf("@%s %q on %q: matched=%v, expected ret=%d", c.Name, c.Param, c.Input, r.Matched, c.Ret))
		}
		for i, g := range c.ReGroups {
			if i >= len(r.Groups) || r.Groups[i] != g {
				msgs = append(msgs, fmt.Sprintf("@%s %q on %q: group %d = %q, expected %q", c.Name, c.Param, c.Input, i, at(r.Groups, i), g))
				break
			}
		}
	default:
		if !r.Matched {
			msgs = append(msgs, fmt.Sprintf("t:%s on %q: rule did not run", c.Name, c.Input))
		} else if r.Output != c.Output {
			msgs = append(msgs, fmt.Sprintf("t:%s on %q: output %q, expected %q", c.Name, c.Input, r.Output, c.Output))
		}
	}
	return msgs
}

func at(s []string, i int) string {
	if i < len(s) {
		return s[i]
	}
	return "<none>"
}
