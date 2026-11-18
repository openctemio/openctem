//go:build authscenarios

// Package authscenarios is the sign-in scenario suite: everything between
// "a person arrives" and "they are working inside an organization", and
// leaving and coming back. Each scenario signs a person in with one method,
// meets an organization with one set of rules through one membership state,
// and checks the answers against the specification (model_test.go) and the
// invariants (no dead end, no bypass, a reason code on every refusal, no
// server error).
//
// It runs against a scratch stack: ci/run.sh starts one from this tree (or,
// with AUTHSCEN_SERVER_DIR, from another tree such as a release checkout),
// runs the suite and removes the stack. Federated sign-ins are seeded as
// their callbacks leave them (no identity provider round trip): the suite
// tests what happens after the provider said yes.
//
// Scenarios that fail on the current code are listed, with the expected
// outcome, in known-failures.txt: they still run, a listed failure is
// reported instead of failing the job, and a listed scenario that passes
// fails the job until its line is removed. The design is
// server/docs/development/auth-scenarios.md.
package authscenarios

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
)

// loadKnownFailures reads known-failures.txt: one scenario id per line,
// optionally followed by "#" and the expected outcome.
func loadKnownFailures(t *testing.T) map[string]string {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	f, err := os.Open(filepath.Join(filepath.Dir(here), "known-failures.txt"))
	if err != nil {
		t.Fatalf("known-failures.txt: %v", err)
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id, why, _ := strings.Cut(line, "#")
		out[strings.TrimSpace(id)] = strings.TrimSpace(why)
	}
	return out
}

// checkStaleKnown fails on a known-failures line that names no scenario of
// the test (a renamed or removed scenario must not hide behind the list).
func checkStaleKnown(t *testing.T, known map[string]string, seen map[string]bool, test string) {
	prefixes := map[string]bool{}
	for id := range seen {
		prefixes[strings.SplitN(id, "/", 2)[0]] = true
	}
	for id := range known {
		if prefixes[strings.SplitN(id, "/", 2)[0]] && !seen[id] {
			t.Errorf("%s: known-failures.txt names %q, which is not a scenario", test, id)
		}
	}
}

var (
	reportMu sync.Mutex
	reported []*run
)

func report(r *run) {
	reportMu.Lock()
	defer reportMu.Unlock()
	reported = append(reported, r)
}

// TestMain writes the JSON report (AUTHSCEN_REPORT) after the run.
func TestMain(m *testing.M) {
	code := m.Run()
	if path := os.Getenv("AUTHSCEN_REPORT"); path != "" {
		reportMu.Lock()
		sort.Slice(reported, func(i, j int) bool { return reported[i].ID < reported[j].ID })
		raw, _ := json.MarshalIndent(reported, "", "  ")
		reportMu.Unlock()
		_ = os.WriteFile(path, raw, 0o600)
	}
	os.Exit(code)
}
