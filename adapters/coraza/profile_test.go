package coraza

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRepoRootContainsSpec(t *testing.T) {
	if _, err := os.Stat(filepath.Join(RepoRoot(), "spec", "00-conventions.md")); err != nil {
		t.Fatalf("RepoRoot() = %s: %v", RepoRoot(), err)
	}
}

func TestLoadProfiles(t *testing.T) {
	profiles, err := LoadProfiles(RepoRoot())
	if err != nil {
		t.Fatal(err)
	}
	var p *Profile
	for i := range profiles {
		if profiles[i].Path == "tests/engine/directives/secruleengine-on.yaml" {
			p = &profiles[i]
		}
	}
	if p == nil {
		t.Fatal("secruleengine-on.yaml not loaded")
	}
	if len(p.Tests) != 2 || p.Tests[0].Stages[0].Stage.Input.URI != "/?attack=1" {
		t.Fatalf("unexpected profile shape: %+v", p.Tests)
	}
	if it := p.Tests[0].Stages[0].Stage.Output.Interruption; it == nil || it.Status != 403 || it.Action != "deny" {
		t.Fatalf("interruption = %+v", it)
	}
}

func TestLoadUnitCases(t *testing.T) {
	cases, err := LoadUnitCases(RepoRoot())
	if err != nil {
		t.Fatal(err)
	}
	b64 := cases["tests/unit/transformations/base64Decode.json"]
	if len(b64) != 4 || b64[0].Type != "tfn" || b64[1].Output != "TestCase" {
		t.Fatalf("base64Decode cases: %+v", b64)
	}
	rx := cases["tests/unit/operators/rx.json"]
	if len(rx) == 0 || !rx[0].HasParam {
		t.Fatalf("rx cases: %+v", rx)
	}
}

func TestLatin1AndEscape(t *testing.T) {
	if got := latin1("Aé\u0000"); string(got) != "A\xe9\x00" || len(got) != 3 {
		t.Fatalf("latin1 = %q", got)
	}
	if got := escapeParam(`a"b\c`); got != `a\"b\c` {
		t.Fatalf("escapeParam = %q", got)
	}
}
