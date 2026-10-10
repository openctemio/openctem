package vex

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

var now = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func valid() *Statement {
	return &Statement{VulnID: " cve-2024-3094 ", ProductID: shared.NewID(), Status: StatusNotAffected,
		Justification: "vulnerable_code_not_present", Origin: OriginManual}
}

func TestNormalize(t *testing.T) {
	s := valid()
	s.Versions = []string{"2.0", " 1.0 ", "2.0", ""}
	if err := s.Normalize(now); err != nil {
		t.Fatal(err)
	}
	if s.VulnID != "CVE-2024-3094" {
		t.Errorf("vuln id %q", s.VulnID)
	}
	if len(s.Versions) != 2 || s.Versions[0] != "1.0" || s.Versions[1] != "2.0" {
		t.Errorf("versions %v (sorted, deduplicated)", s.Versions)
	}

	past := now.Add(-time.Hour)
	far := now.Add(6 * 365 * 24 * time.Hour)
	cases := map[string]func(*Statement){
		"bad vuln id":               func(s *Statement) { s.VulnID = "x" },
		"vuln id with spaces":       func(s *Statement) { s.VulnID = "CVE 2024" },
		"unknown status":            func(s *Statement) { s.Status = "maybe" },
		"unknown justification":     func(s *Statement) { s.Justification = "trust_me" },
		"justification on affected": func(s *Statement) { s.Status = StatusAffected },
		"not_affected without why":  func(s *Statement) { s.Justification = "" },
		"versions and range":        func(s *Statement) { s.Versions = []string{"1"}; s.VersionRange = "<2" },
		"bad range":                 func(s *Statement) { s.VersionRange = "~1.0" },
		"version with comma":        func(s *Statement) { s.Versions = []string{"1,2"} },
		"expiry in the past":        func(s *Statement) { s.ExpiresAt = &past },
		"expiry too far":            func(s *Statement) { s.ExpiresAt = &far },
		"impact statement too long": func(s *Statement) { s.ImpactStatement = strings.Repeat("a", MaxStatementLen+1) },
		"unknown origin":            func(s *Statement) { s.Origin = "hearsay" },
		"too many versions":         func(s *Statement) { s.Versions = make([]string, MaxVersions+1) },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			s := valid()
			mut(s)
			if err := s.Normalize(now); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want validation error, got %v", err)
			}
		})
	}

	// An impact statement alone explains not_affected; control characters
	// are stripped.
	s = valid()
	s.Justification, s.ImpactStatement = "", "only\x00 in tests\x07"
	if err := s.Normalize(now); err != nil || s.ImpactStatement != "only in tests" {
		t.Fatalf("impact statement: %v %q", err, s.ImpactStatement)
	}
}

func TestRange(t *testing.T) {
	r, err := ParseRange(" >= 1.2.0 , <1.4.3")
	if err != nil {
		t.Fatal(err)
	}
	if r.String() != ">=1.2.0,<1.4.3" {
		t.Errorf("canonical %q", r.String())
	}
	for v, want := range map[string]bool{
		"1.2.0": true, "1.3.9": true, "1.4.2": true, "1.4.3": false, "1.1.9": false, "v1.3": true,
		"1.4.3-rc1": true, "latest": false, "": false,
	} {
		if got := r.Contains(v); got != want {
			t.Errorf("Contains(%q) = %v, want %v", v, got, want)
		}
	}
	if r, _ := ParseRange("!=2.0"); r.Contains("2.0.0") || !r.Contains("2.1") {
		t.Error("!= term")
	}
	for _, bad := range []string{"", "1.0", ">=", ">=x.y", "<1,<2,<3,<4,<5,<6,<7,<8,<9"} {
		if _, err := ParseRange(bad); err == nil {
			t.Errorf("ParseRange(%q) accepted", bad)
		}
	}
}

func ref(product, asset shared.ID, version string, vulns ...string) *FindingRef {
	return &FindingRef{ID: shared.NewID(), AssetID: asset, ProductID: product, Version: version, VulnIDs: vulns,
		Status: "new", Source: "sca"}
}

func TestCoversAndPick(t *testing.T) {
	product, other, a1, a2 := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	all := &Statement{ID: shared.NewID(), VulnID: "CVE-1", ProductID: product, Status: StatusNotAffected, UpdatedAt: now}
	listed := &Statement{ID: shared.NewID(), VulnID: "CVE-1", ProductID: product, Versions: []string{"1.0"}, Status: StatusAffected, UpdatedAt: now}
	ranged := &Statement{ID: shared.NewID(), VulnID: "CVE-1", ProductID: product, VersionRange: "<2", Status: StatusFixed, UpdatedAt: now}
	onA1 := &Statement{ID: shared.NewID(), VulnID: "CVE-1", ProductID: product, AssetID: &a1, Status: StatusUnderInvestigation, UpdatedAt: now}

	f := ref(product, a2, "1.0", "GHSA-X", "cve-1")
	if !all.Covers(f) || !listed.Covers(f) || !ranged.Covers(f) || onA1.Covers(f) {
		t.Error("covers on a2 at 1.0")
	}
	if all.Covers(ref(other, a2, "1.0", "CVE-1")) {
		t.Error("another package")
	}
	if all.Covers(ref(product, a2, "1.0", "CVE-2")) {
		t.Error("another vulnerability")
	}
	if listed.Covers(ref(product, a2, "1.1", "CVE-1")) || ranged.Covers(ref(product, a2, "2.0", "CVE-1")) {
		t.Error("version outside the statement")
	}

	stmts := []*Statement{all, ranged, listed, onA1}
	if got := Pick(stmts, f, now); got != listed {
		t.Errorf("listed versions win over a range: %v", got)
	}
	if got := Pick(stmts, ref(product, a1, "1.0", "CVE-1"), now); got != onA1 {
		t.Errorf("asset-bound wins: %v", got)
	}
	if got := Pick(stmts, ref(product, a2, "3.0", "CVE-1"), now); got != all {
		t.Errorf("every-version statement: %v", got)
	}
	past := now.Add(-time.Minute)
	expired := &Statement{ID: shared.NewID(), VulnID: "CVE-1", ProductID: product, AssetID: &a2, Status: StatusNotAffected, ExpiresAt: &past}
	if got := Pick([]*Statement{expired}, f, now); got != nil {
		t.Error("an expired statement governs nothing")
	}
}

func TestDecide(t *testing.T) {
	product, asset := shared.NewID(), shared.NewID()
	na := &Statement{ID: shared.NewID(), VulnID: "CVE-1", ProductID: product, Status: StatusNotAffected,
		Justification: "component_not_present", UpdatedAt: now}
	fixed := &Statement{ID: shared.NewID(), VulnID: "CVE-1", ProductID: product, Status: StatusFixed, UpdatedAt: now}
	affected := &Statement{ID: shared.NewID(), VulnID: "CVE-1", ProductID: product, Status: StatusAffected, UpdatedAt: now}

	open := ref(product, asset, "1", "CVE-1")
	e := Decide(open, na)
	if e == nil || e.NewStatus != "false_positive" || e.ResolutionMethod != ResolutionNotAffected || e.Statement != na {
		t.Fatalf("not_affected closes an open finding: %+v", e)
	}
	if e := Decide(open, fixed); e == nil || e.NewStatus != "resolved" || e.ResolutionMethod != ResolutionFixed {
		t.Fatalf("fixed resolves: %+v", e)
	}
	if e := Decide(open, affected); e == nil || e.Changes() || e.Statement != affected {
		t.Fatalf("affected annotates only: %+v", e)
	}

	human := ref(product, asset, "1", "CVE-1")
	human.Source = "pentest"
	if e := Decide(human, na); e == nil || e.Changes() {
		t.Fatalf("a human-sourced finding is never closed: %+v", e)
	}
	accepted := ref(product, asset, "1", "CVE-1")
	accepted.Status = "accepted"
	if e := Decide(accepted, na); e == nil || e.Changes() {
		t.Fatalf("a person's disposition is kept: %+v", e)
	}

	closed := ref(product, asset, "1", "CVE-1")
	closed.Status, closed.ResolutionMethod, closed.StatementID = "false_positive", ResolutionNotAffected, &na.ID
	if e := Decide(closed, nil); e == nil || e.NewStatus != "new" || e.Statement != nil {
		t.Fatalf("withdrawn: false positive reopens to new: %+v", e)
	}
	if e := Decide(closed, affected); e == nil || e.NewStatus != "new" {
		t.Fatalf("now affected: reopens: %+v", e)
	}
	if e := Decide(closed, fixed); e == nil || e.NewStatus != "resolved" || e.ResolutionMethod != ResolutionFixed {
		t.Fatalf("not_affected -> fixed switches the closure: %+v", e)
	}
	resolved := ref(product, asset, "1", "CVE-1")
	resolved.Status, resolved.ResolutionMethod, resolved.StatementID = "resolved", ResolutionFixed, &fixed.ID
	if e := Decide(resolved, nil); e == nil || e.NewStatus != "confirmed" {
		t.Fatalf("withdrawn: resolved reopens to confirmed: %+v", e)
	}

	// Unchanged: same statement at the same version -> nothing to write.
	closed.VEXAt = &na.UpdatedAt
	if e := Decide(closed, na); e != nil {
		t.Fatalf("no-op expected: %+v", e)
	}
	if e := Decide(ref(product, asset, "1", "CVE-1"), nil); e != nil {
		t.Fatal("a finding without a statement and no governing statement is left alone")
	}
}

// Every status move a statement makes is an edge of the finding lifecycle.
func TestDecideFollowsLifecycle(t *testing.T) {
	for _, from := range vulnerability.AutoCloseFromStatuses() {
		for _, to := range []vulnerability.FindingStatus{vulnerability.FindingStatusFalsePositive, vulnerability.FindingStatusResolved} {
			if err := vulnerability.CheckPlatformTransitions(to, from); err != nil {
				t.Errorf("close %s -> %s: %v", from, to, err)
			}
		}
	}
	if err := vulnerability.CheckPlatformTransitions(vulnerability.FindingStatusNew, vulnerability.FindingStatusFalsePositive); err != nil {
		t.Errorf("reopen false_positive -> new: %v", err)
	}
	if err := vulnerability.CheckPlatformTransitions(vulnerability.FindingStatusConfirmed, vulnerability.FindingStatusResolved); err != nil {
		t.Errorf("reopen resolved -> confirmed: %v", err)
	}
}
