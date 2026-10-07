package coraza

import (
	"fmt"
	"path/filepath"
	"testing"
)

// implemented lists the Extended feature anchors Coraza 3.8.1 implements; profiles whose
// requires: names anything else are skipped.
var implemented = map[string]bool{}

func needsUnimplemented(p Profile) (string, bool) {
	for _, r := range p.Requires {
		if !implemented[r] {
			return r, true
		}
	}
	return "", false
}

// runProfile returns every mismatch of every stage, prefixed with its location.
func runProfile(t *testing.T, p Profile) []string {
	t.Helper()
	expectError := false
	for _, tc := range p.Tests {
		for _, st := range tc.Stages {
			if st.Stage.Output.ExpectError {
				expectError = true
			}
		}
	}
	waf, log, err := BuildWAF(p, t.TempDir())
	if expectError {
		if err == nil {
			return []string{"configuration loaded but expect_error was set"}
		}
		return nil
	}
	if err != nil {
		return []string{"configuration failed to load: " + err.Error()}
	}
	var failures []string
	for _, tc := range p.Tests {
		for i, st := range tc.Stages {
			o := RunStage(waf, log, st.Stage)
			for _, m := range CheckStage(o, st.Stage.Output) {
				failures = append(failures, fmt.Sprintf("%s / stage %d: %s", tc.Title, i+1, m))
			}
		}
	}
	return failures
}

func reportGated(t *testing.T, path string, gaps map[string]string, failures []string) {
	t.Helper()
	reason, expected := gaps[path]
	switch {
	case expected && len(failures) == 0:
		t.Fatalf("known-gaps row is obsolete: remove the row for %s (%s)", path, reason)
	case expected:
		for _, f := range failures {
			t.Log("expected (known gap: " + reason + "): " + f)
		}
	default:
		for _, f := range failures {
			t.Error(f)
		}
	}
}

func TestEngine(t *testing.T) {
	root := RepoRoot()
	gaps, err := LoadGaps(filepath.Join(root, "compat", "known-gaps.md"), "coraza")
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := LoadProfiles(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range profiles {
		p := p
		t.Run(p.Path, func(t *testing.T) {
			if reason, skip := needsUnimplemented(p); skip {
				t.Skip("requires " + reason)
			}
			reportGated(t, p.Path, gaps, runProfile(t, p))
		})
	}
}
