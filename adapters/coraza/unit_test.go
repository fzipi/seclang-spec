package coraza

import "testing"

func TestUnitOperatorAndTransformation(t *testing.T) {
	op := UnitCase{Type: "op", Name: "contains", Param: "abc", HasParam: true, Input: "xabcx", Ret: 1}
	r, err := RunUnit(op, t.TempDir())
	if err != nil || !r.Matched {
		t.Fatalf("contains: matched=%v err=%v", r.Matched, err)
	}
	op.Input = "nothing"
	if r, _ := RunUnit(op, t.TempDir()); r.Matched {
		t.Fatal("contains must not match")
	}
	tf := UnitCase{Type: "tfn", Name: "lowercase", Input: "ABC\u0000D", Output: "abc\u0000d", Ret: 1}
	r, err = RunUnit(tf, t.TempDir())
	if err != nil || r.Output != "abc\u0000d" {
		t.Fatalf("lowercase: output=%q err=%v", r.Output, err)
	}
	rx := UnitCase{Type: "op", Name: "rx", Param: "^(a)(b)", HasParam: true, Input: "abc", Ret: 1, ReGroups: []string{"ab", "a", "b"}}
	r, err = RunUnit(rx, t.TempDir())
	if err != nil || !r.Matched || len(r.Groups) < 3 || r.Groups[1] != "a" || r.Groups[2] != "b" {
		t.Fatalf("rx groups=%v err=%v", r.Groups, err)
	}
}

func TestUnitHighByteParamAndInput(t *testing.T) {
	// Param and input are byte strings: byte 0xE9 on both sides must compare equal.
	c := UnitCase{Type: "op", Name: "streq", Param: "\u00e9", HasParam: true, Input: "\u00e9", Ret: 1}
	r, err := RunUnit(c, t.TempDir())
	if err != nil || !r.Matched {
		t.Fatalf("high-byte param: matched=%v err=%v", r.Matched, err)
	}
}

func TestUnitRulesEscapesParam(t *testing.T) {
	rules := unitRules(UnitCase{Type: "op", Name: "rx", Param: `a"b\d`, HasParam: true})
	if !contains(rules, `"@rx a\"b\d"`) {
		t.Fatalf("rules = %s", rules)
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (func() bool { for i := 0; i+len(sub) <= len(s); i++ { if s[i:i+len(sub)] == sub { return true } }; return false })() }
