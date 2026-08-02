package threatmodel

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	tmdom "github.com/openctemio/api/pkg/domain/threatmodel"
)

func threat(t *testing.T, tactic, techniqueID, mitigationID string, status tmdom.ThreatStatus, score float64) *tmdom.ThreatModelThreat {
	t.Helper()
	tt, err := tmdom.NewThreatModelThreat(shared.NewID(), shared.NewID(), status)
	if err != nil {
		t.Fatalf("NewThreatModelThreat: %v", err)
	}
	tt.Tactic = tactic
	tt.TechniqueID = techniqueID
	tt.MitigationID = mitigationID
	tt.Score = score
	return tt
}

func findTech(t *testing.T, cov Coverage, tactic, techniqueID string) TechniqueCoverage {
	t.Helper()
	for _, tac := range cov.Tactics {
		if tac.Tactic != tactic {
			continue
		}
		for _, tc := range tac.Techniques {
			if tc.TechniqueID == techniqueID {
				return tc
			}
		}
	}
	t.Fatalf("technique %s/%s not found in coverage", tactic, techniqueID)
	return TechniqueCoverage{}
}

// TestBuildCoverage_WorstCaseRollup: a technique with one open + two theoretical
// threats rolls up to open, with the correct per-status counts and max score.
func TestBuildCoverage_WorstCaseRollup(t *testing.T) {
	threats := []*tmdom.ThreatModelThreat{
		threat(t, "Credential Access", "T1552", "M1022", tmdom.StatusOpen, 7.2),
		threat(t, "Credential Access", "T1552", "M1027", tmdom.StatusTheoretical, 3.0),
		threat(t, "Credential Access", "T1552", "M1022", tmdom.StatusTheoretical, 5.5),
	}

	cov := buildCoverage(threats, nil)

	tc := findTech(t, cov, "Credential Access", "T1552")
	if tc.Status != "open" {
		t.Fatalf("worst-case status = %q, want open", tc.Status)
	}
	if tc.Counts.Open != 1 || tc.Counts.Theoretical != 2 {
		t.Fatalf("counts = %+v, want open=1 theoretical=2", tc.Counts)
	}
	if tc.ThreatCount != 3 {
		t.Fatalf("threat_count = %d, want 3", tc.ThreatCount)
	}
	if tc.MaxScore != 7.2 {
		t.Fatalf("max_score = %v, want 7.2", tc.MaxScore)
	}
	// Fallback mitigation ids from the threats (no catalog meta), distinct+sorted.
	if len(tc.MitigationIDs) != 2 || tc.MitigationIDs[0] != "M1022" || tc.MitigationIDs[1] != "M1027" {
		t.Fatalf("mitigation_ids = %v, want [M1022 M1027]", tc.MitigationIDs)
	}
}

// TestBuildCoverage_RollupPrecedence checks the full precedence ladder
// open>accepted>mitigated>covered>theoretical for the worst-case status.
func TestBuildCoverage_RollupPrecedence(t *testing.T) {
	cases := []struct {
		name     string
		statuses []tmdom.ThreatStatus
		want     string
	}{
		{"accepted beats mitigated/covered", []tmdom.ThreatStatus{tmdom.StatusCovered, tmdom.StatusMitigated, tmdom.StatusAccepted}, "accepted"},
		{"mitigated beats covered", []tmdom.ThreatStatus{tmdom.StatusCovered, tmdom.StatusMitigated}, "mitigated"},
		{"covered beats theoretical", []tmdom.ThreatStatus{tmdom.StatusTheoretical, tmdom.StatusCovered}, "covered"},
		{"all theoretical", []tmdom.ThreatStatus{tmdom.StatusTheoretical, tmdom.StatusTheoretical}, "theoretical"},
	}
	for _, tccase := range cases {
		t.Run(tccase.name, func(t *testing.T) {
			threats := make([]*tmdom.ThreatModelThreat, 0, len(tccase.statuses))
			for _, s := range tccase.statuses {
				threats = append(threats, threat(t, "Discovery", "T1046", "", s, 1))
			}
			cov := buildCoverage(threats, nil)
			tc := findTech(t, cov, "Discovery", "T1046")
			if tc.Status != tccase.want {
				t.Fatalf("status = %q, want %q", tc.Status, tccase.want)
			}
		})
	}
}

// TestBuildCoverage_TacticGroupingAndOrder: techniques group under their tactic,
// and tactics come out in canonical kill-chain order regardless of input order.
func TestBuildCoverage_TacticGroupingAndOrder(t *testing.T) {
	threats := []*tmdom.ThreatModelThreat{
		threat(t, "Impact", "T1485", "", tmdom.StatusOpen, 9),
		threat(t, "Initial Access", "T1190", "", tmdom.StatusMitigated, 5),
		threat(t, "Credential Access", "T1552", "", tmdom.StatusTheoretical, 2),
		threat(t, "Credential Access", "T1003", "", tmdom.StatusOpen, 8),
		threat(t, "Reconnaissance", "T1595", "", tmdom.StatusTheoretical, 1),
	}

	cov := buildCoverage(threats, nil)

	gotOrder := make([]string, 0, len(cov.Tactics))
	for _, tac := range cov.Tactics {
		gotOrder = append(gotOrder, tac.Tactic)
	}
	want := []string{"Reconnaissance", "Initial Access", "Credential Access", "Impact"}
	if len(gotOrder) != len(want) {
		t.Fatalf("tactic order = %v, want %v", gotOrder, want)
	}
	for i := range want {
		if gotOrder[i] != want[i] {
			t.Fatalf("tactic order = %v, want %v", gotOrder, want)
		}
	}

	// Techniques within a tactic are ordered by technique id.
	var ca TacticCoverage
	for _, tac := range cov.Tactics {
		if tac.Tactic == "Credential Access" {
			ca = tac
		}
	}
	if len(ca.Techniques) != 2 || ca.Techniques[0].TechniqueID != "T1003" || ca.Techniques[1].TechniqueID != "T1552" {
		t.Fatalf("credential-access techniques = %+v, want [T1003, T1552]", ca.Techniques)
	}
}

// TestBuildCoverage_UnknownTacticSortsLast: a tactic not in the kill-chain list
// sorts after the known ones, alphabetically.
func TestBuildCoverage_UnknownTacticSortsLast(t *testing.T) {
	threats := []*tmdom.ThreatModelThreat{
		threat(t, "Zeta Custom", "T9002", "", tmdom.StatusOpen, 1),
		threat(t, "Alpha Custom", "T9001", "", tmdom.StatusOpen, 1),
		threat(t, "Impact", "T1485", "", tmdom.StatusOpen, 1),
	}
	cov := buildCoverage(threats, nil)
	if cov.Tactics[0].Tactic != "Impact" {
		t.Fatalf("first tactic = %q, want Impact (known before unknown)", cov.Tactics[0].Tactic)
	}
	if cov.Tactics[1].Tactic != "Alpha Custom" || cov.Tactics[2].Tactic != "Zeta Custom" {
		t.Fatalf("unknown tactic order = %q,%q want Alpha Custom,Zeta Custom", cov.Tactics[1].Tactic, cov.Tactics[2].Tactic)
	}
}

// TestBuildCoverage_Totals: totals count technique cells (not threats) by their
// worst-case status, and coverage_pct = addressed/(open+addressed).
func TestBuildCoverage_Totals(t *testing.T) {
	threats := []*tmdom.ThreatModelThreat{
		// T1552 → open (worst-case), one cell counted as open.
		threat(t, "Credential Access", "T1552", "", tmdom.StatusOpen, 7),
		threat(t, "Credential Access", "T1552", "", tmdom.StatusTheoretical, 2),
		// T1003 → mitigated cell.
		threat(t, "Credential Access", "T1003", "", tmdom.StatusMitigated, 4),
		// T1190 → accepted cell.
		threat(t, "Initial Access", "T1190", "", tmdom.StatusAccepted, 3),
		// T1046 → theoretical cell (counts to total, not to open/addressed).
		threat(t, "Discovery", "T1046", "", tmdom.StatusTheoretical, 1),
	}

	cov := buildCoverage(threats, nil)

	tot := cov.Totals
	if tot.Techniques != 4 {
		t.Fatalf("techniques total = %d, want 4", tot.Techniques)
	}
	if tot.Open != 1 || tot.Mitigated != 1 || tot.Accepted != 1 || tot.Theoretical != 1 {
		t.Fatalf("totals = %+v, want open=1 mitigated=1 accepted=1 theoretical=1", tot)
	}
	// addressed = mitigated(1)+covered(0)+accepted(1) = 2; denom = open(1)+2 = 3.
	want := 2.0 / 3.0 * 100
	if diff := tot.CoveragePct - want; diff > 0.001 || diff < -0.001 {
		t.Fatalf("coverage_pct = %v, want %v", tot.CoveragePct, want)
	}
}

// TestBuildCoverage_CatalogEnrichment: technique names and mitigation lists come
// from the catalog meta when present (overriding the threat-derived fallback).
func TestBuildCoverage_CatalogEnrichment(t *testing.T) {
	threats := []*tmdom.ThreatModelThreat{
		threat(t, "Credential Access", "T1552", "M1022", tmdom.StatusOpen, 7),
	}
	meta := map[string]TechniqueMeta{
		"T1552": {Name: "Unsecured Credentials", MitigationIDs: []string{"M1027", "M1022"}},
	}
	cov := buildCoverage(threats, meta)
	tc := findTech(t, cov, "Credential Access", "T1552")
	if tc.TechniqueName != "Unsecured Credentials" {
		t.Fatalf("technique_name = %q, want Unsecured Credentials", tc.TechniqueName)
	}
	// Catalog mitigation ids win, sorted.
	if len(tc.MitigationIDs) != 2 || tc.MitigationIDs[0] != "M1022" || tc.MitigationIDs[1] != "M1027" {
		t.Fatalf("mitigation_ids = %v, want [M1022 M1027]", tc.MitigationIDs)
	}
}

// TestBuildCoverage_SkipsEmptyTechnique: threats with no technique id are skipped.
func TestBuildCoverage_SkipsEmptyTechnique(t *testing.T) {
	threats := []*tmdom.ThreatModelThreat{
		threat(t, "Discovery", "", "", tmdom.StatusOpen, 1),
	}
	cov := buildCoverage(threats, nil)
	if len(cov.Tactics) != 0 || cov.Totals.Techniques != 0 {
		t.Fatalf("expected empty coverage, got %+v", cov)
	}
}
