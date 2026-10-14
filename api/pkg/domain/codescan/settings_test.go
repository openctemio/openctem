package codescan

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestDefaults(t *testing.T) {
	d := Defaults(shared.NewID())
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	if !d.Matches("main", "main") || !d.Matches("develop", "main") || d.Matches("feature/x", "main") {
		t.Fatalf("defaults protect the default branch and develop only: %+v", d.ProtectedBranches)
	}
}

func TestValidateNormalizes(t *testing.T) {
	s := Settings{ProtectedBranches: []string{" main ", "main", "release/*", DefaultBranchToken},
		Capabilities: []string{"IaC", "sast", "sast"}, Schedule: ScheduleDaily, Routing: RoutingTenant}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(s.ProtectedBranches) != 3 || s.Capabilities[0] != CapabilitySAST || s.Capabilities[1] != CapabilityIaC || len(s.Capabilities) != 2 {
		t.Fatalf("%+v", s)
	}
}

func TestValidateRefuses(t *testing.T) {
	base := func() Settings {
		return Settings{ProtectedBranches: []string{"main"}, Capabilities: []string{"sast"}, Schedule: ScheduleWeekly, Routing: RoutingAuto}
	}
	many := make([]string, MaxProtectedBranches+1)
	for i := range many {
		many[i] = "b" + string(rune('a'+i))
	}
	for name, mut := range map[string]func(*Settings){
		"no branch":        func(s *Settings) { s.ProtectedBranches = []string{" "} },
		"too many":         func(s *Settings) { s.ProtectedBranches = many },
		"option branch":    func(s *Settings) { s.ProtectedBranches = []string{"--all"} },
		"dotdot":           func(s *Settings) { s.ProtectedBranches = []string{"a..b"} },
		"reflog":           func(s *Settings) { s.ProtectedBranches = []string{"main@{1}"} },
		"question glob":    func(s *Settings) { s.ProtectedBranches = []string{"rel?ase"} },
		"no capability":    func(s *Settings) { s.Capabilities = nil },
		"bad capability":   func(s *Settings) { s.Capabilities = []string{"dast"} },
		"bad schedule":     func(s *Settings) { s.Schedule = "hourly" },
		"bad routing":      func(s *Settings) { s.Routing = "anywhere" },
		"control in name":  func(s *Settings) { s.ProtectedBranches = []string{"ma\nin"} },
		"trailing slash":   func(s *Settings) { s.ProtectedBranches = []string{"release/"} },
		"lock suffix":      func(s *Settings) { s.ProtectedBranches = []string{"main.lock"} },
		"leading slash":    func(s *Settings) { s.ProtectedBranches = []string{"/main"} },
		"bracket pattern":  func(s *Settings) { s.ProtectedBranches = []string{"[a-z]*"} },
		"backslash":        func(s *Settings) { s.ProtectedBranches = []string{`a\b`} },
		"colon (refspec)":  func(s *Settings) { s.ProtectedBranches = []string{"a:b"} },
		"tilde (revision)": func(s *Settings) { s.ProtectedBranches = []string{"main~1"} },
	} {
		s := base()
		mut(&s)
		if err := s.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestMatches(t *testing.T) {
	s := Settings{ProtectedBranches: []string{DefaultBranchToken, "release/*"}}
	for branch, want := range map[string]bool{"trunk": true, "release/1.2": true, "release/1/2": false, "develop": false, "release": false} {
		if got := s.Matches(branch, "trunk"); got != want {
			t.Errorf("%s: %v", branch, got)
		}
	}
	if s.Matches("trunk", "") {
		t.Error("the default-branch token matched with no known default branch")
	}
}

func TestEffective(t *testing.T) {
	tenant := shared.NewID()
	repo := &Settings{Schedule: ScheduleDaily}
	tmpl := &Settings{Schedule: ScheduleMonthly}
	if s, src := Effective(tenant, repo, tmpl); src != SourceRepository || s.Schedule != ScheduleDaily {
		t.Fatal(src)
	}
	if s, src := Effective(tenant, nil, tmpl); src != SourceTemplate || s.Schedule != ScheduleMonthly {
		t.Fatal(src)
	}
	if s, src := Effective(tenant, nil, nil); src != SourceDefault || s.Schedule != ScheduleWeekly || s.TenantID != tenant {
		t.Fatal(src)
	}
}
