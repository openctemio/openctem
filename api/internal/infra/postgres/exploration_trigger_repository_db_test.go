package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/exploration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func (f *coverageFixture) namedAsset(t *testing.T, typ string) shared.ID {
	t.Helper()
	id := shared.NewID()
	f.exec(t, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, $4)`, id, f.tenant, id.String()+".example.com", typ)
	return id
}

func (f *coverageFixture) exposure(t *testing.T, asset shared.ID, eventType, state, source string) {
	t.Helper()
	f.exec(t, `INSERT INTO exposure_events (tenant_id, asset_id, event_type, severity, state, title, fingerprint, source)
		VALUES ($1, $2, $3, 'high', $4, 't', $5, $6)`, f.tenant, asset, eventType, state, "fp-"+shared.NewID().String(), source)
}

func candidateIDs(cs []exploration.Candidate) map[shared.ID]exploration.Candidate {
	out := map[shared.ID]exploration.Candidate{}
	for _, c := range cs {
		out[c.AssetID] = c
	}
	return out
}

// Only the platform's own DNS check opens a takeover question; another
// tenant's alias, an imported exposure, an alias already found claimable and
// an alias already asked about are left out.
func TestExplorationTriggers_DanglingAliases_DB(t *testing.T) {
	f := newCoverageFixture(t)
	other := newCoverageFixture(t)
	triggers := NewExplorationTriggerRepository(&DB{DB: f.db})
	repo := NewExplorationRepository(&DB{DB: f.db})
	ctx := context.Background()

	dangling := f.namedAsset(t, "subdomain")
	f.exposure(t, dangling, "dangling_cname", "active", "easm_dns")
	imported := f.namedAsset(t, "subdomain")
	f.exposure(t, imported, "dangling_cname", "active", "import")
	claimed := f.namedAsset(t, "subdomain")
	f.exposure(t, claimed, "dangling_cname", "active", "easm_dns")
	f.exposure(t, claimed, "subdomain_takeover", "active", "nuclei")
	resolved := f.namedAsset(t, "subdomain")
	f.exposure(t, resolved, "dangling_cname", "resolved", "easm_dns")
	theirs := other.namedAsset(t, "subdomain")
	other.exposure(t, theirs, "dangling_cname", "active", "easm_dns")

	got, err := triggers.DanglingAliases(ctx, f.tenant, "dns.takeover_check", 50)
	if err != nil {
		t.Fatal(err)
	}
	ids := candidateIDs(got)
	if len(ids) != 1 || ids[dangling].AssetID != dangling {
		t.Fatalf("candidates = %v, want only the platform-checked dangling alias", ids)
	}
	if ev := ids[dangling].Evidence; len(ev) != 1 || ev[0].EndKind != exploration.EndAsset {
		t.Fatalf("evidence = %+v", ev)
	}

	// Asked: a live lead leaves the subject out of the next pass.
	if _, created := leadOn(t, repo, f, dangling); !created {
		t.Fatal("lead not opened")
	}
	if got, _ := triggers.DanglingAliases(ctx, f.tenant, "dns.takeover_check", 50); len(got) != 0 {
		t.Fatalf("an asked subject was offered again: %d", len(got))
	}
}

// A version match below the likely threshold that is in KEV or critical
// asks for the version to be confirmed; a likely match, a scanner's finding
// and a closed finding do not.
func TestExplorationTriggers_UnconfirmedCriticalMatches_DB(t *testing.T) {
	f := newCoverageFixture(t)
	triggers := NewExplorationTriggerRepository(&DB{DB: f.db})
	ctx := context.Background()

	vm := func(asset shared.ID, confidence int, kev bool, severity, status string) shared.ID {
		id := f.finding(t, asset, "version-match", "", nil)
		f.exec(t, `UPDATE findings SET confidence = $2, is_in_kev = $3, severity = $4, status = $5 WHERE id = $1`,
			id, confidence, kev, severity, status)
		return id
	}
	weak := f.namedAsset(t, "host")
	weakFinding := vm(weak, 50, true, "high", "new")
	likely := f.namedAsset(t, "host")
	vm(likely, 90, true, "critical", "new")
	closed := f.namedAsset(t, "host")
	vm(closed, 40, true, "critical", "resolved")
	scanner := f.namedAsset(t, "host")
	sid := f.finding(t, scanner, "nuclei", "", nil)
	f.exec(t, `UPDATE findings SET confidence = 10, is_in_kev = true WHERE id = $1`, sid)

	got, err := triggers.UnconfirmedCriticalMatches(ctx, f.tenant, "version.confirm", 50)
	if err != nil {
		t.Fatal(err)
	}
	ids := candidateIDs(got)
	if len(ids) != 1 {
		t.Fatalf("candidates = %v, want the weak KEV match only", ids)
	}
	ev := ids[weak].Evidence
	if len(ev) != 2 || ev[1].EndKind != exploration.EndFinding || *ev[1].EndID != weakFinding {
		t.Fatalf("evidence = %+v, want the asset and its finding", ev)
	}
}

// A gone asset with an open finding is asked about; a gone asset with only
// closed findings and a live asset are not.
func TestExplorationTriggers_GoneWithOpenFindings_DB(t *testing.T) {
	f := newCoverageFixture(t)
	other := newCoverageFixture(t)
	triggers := NewExplorationTriggerRepository(&DB{DB: f.db})
	ctx := context.Background()

	gone := func(fx *coverageFixture, a shared.ID, state string) {
		fx.exec(t, `INSERT INTO asset_liveness (tenant_id, asset_id, state) VALUES ($1, $2, $3)`, fx.tenant, a, state)
	}
	g1 := f.namedAsset(t, "subdomain")
	gone(f, g1, "gone")
	f.finding(t, g1, "nuclei", "", nil)
	g2 := f.namedAsset(t, "subdomain")
	gone(f, g2, "gone")
	closedOnly := f.finding(t, g2, "nuclei", "", nil)
	f.exec(t, `UPDATE findings SET status = 'resolved' WHERE id = $1`, closedOnly)
	alive := f.namedAsset(t, "subdomain")
	gone(f, alive, "alive")
	f.finding(t, alive, "nuclei", "", nil)
	theirs := other.namedAsset(t, "subdomain")
	gone(other, theirs, "gone")
	other.finding(t, theirs, "nuclei", "", nil)

	got, err := triggers.GoneWithOpenFindings(ctx, f.tenant, "asset.gone_with_findings", 50)
	if err != nil {
		t.Fatal(err)
	}
	ids := candidateIDs(got)
	if len(ids) != 1 || len(ids[g1].Evidence) != 2 {
		t.Fatalf("candidates = %v, want g1 with its finding", ids)
	}
}
