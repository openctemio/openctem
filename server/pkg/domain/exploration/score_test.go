package exploration

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func TestScore_ExpectedValue(t *testing.T) {
	base := ScoreInput{Likelihood: LikelihoodMedium, ValueWeight: 1, Subject: SubjectValue{Criticality: "low"}}
	s0, in := Score(base)
	if s0 <= 0 || in["p_useful"].(float64) != 0.3 {
		t.Fatalf("base score %v inputs %v", s0, in)
	}
	richer := base
	richer.Subject = SubjectValue{Criticality: "critical", Public: true, KEVOrCritical: true, CrownJewel: true}
	if s1, _ := Score(richer); s1 <= s0*40 {
		t.Fatalf("a public crown jewel with KEV must outrank: %v vs %v", s1, s0)
	}
	slow := base
	slow.MeanMs = 600000
	if s2, _ := Score(slow); s2 >= s0 {
		t.Fatalf("a slower tool must score lower: %v vs %v", s2, s0)
	}
	learned := base
	learned.Cell = CellStats{Tried: 20, Useful: 18, RecentTried: 10, RecentUseful: 9}
	if s3, _ := Score(learned); s3 <= s0 {
		t.Fatalf("a cell that usually helps must rise: %v vs %v", s3, s0)
	}
	dead := base
	dead.Cell = CellStats{Tried: 10, RecentTried: 10}
	s4, in4 := Score(dead)
	if in4["demoted"] != true || s4 >= s0*DemoteFactor {
		t.Fatalf("ten useless outcomes demote: %v %v", s4, in4)
	}
}

func mkLead(typ, capability string, score float64, subject shared.ID) *Lead {
	return &Lead{ID: shared.NewID(), Type: typ, Action: Action{Capability: capability}, Score: score,
		SubjectAssetID: &subject, CreatedAt: time.Now()}
}

func TestSelect_ReserveCapsAndBusy(t *testing.T) {
	a, b, c, d := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	tried := map[string]CellStats{CellKey("version.confirm", "probe.http"): {Tried: 5, Useful: 1}}
	open := []*Lead{
		mkLead("version.confirm", "probe.http", 90, a),
		mkLead("version.confirm", "probe.http", 80, b),
		mkLead("version.confirm", "probe.http", 70, c),
		mkLead("version.confirm", "probe.http", 60, d),
		mkLead("dns.takeover_check", "check.takeover", 1, a), // untried cell, lowest score
	}
	got := Select(open, tried, nil, 4)
	if len(got) != 4 {
		t.Fatalf("picked %d", len(got))
	}
	// The untried cell gets a reserved slot despite its score.
	if got[0].Type != "dns.takeover_check" {
		t.Fatalf("first pick %s, want the untried cell", got[0].Type)
	}
	// Then by score, highest first.
	if got[1].Score != 90 || got[2].Score != 80 || got[3].Score != 70 {
		t.Fatalf("order %v %v %v", got[1].Score, got[2].Score, got[3].Score)
	}
	// One running per subject and capability.
	busy := map[string]bool{BusyKey(a.String(), "probe.http"): true}
	for _, l := range Select(open, tried, busy, 5) {
		if *l.SubjectAssetID == a && l.Action.Capability == "probe.http" {
			t.Fatal("a busy subject and capability was picked again")
		}
	}
	dup := []*Lead{mkLead("version.confirm", "probe.http", 5, a), mkLead("asset.gone_with_findings", "probe.http", 4, a)}
	if got := Select(dup, tried, nil, 5); len(got) != 1 {
		t.Fatalf("two leads on one subject and capability picked %d", len(got))
	}
	if Select(open, tried, nil, 0) != nil {
		t.Fatal("no slots, no picks")
	}
}
