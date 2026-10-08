package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Source-asserted resolve (RFC-047 §7.6): only open findings of the same
// tool, on the stated asset and key, last seen no later than the mitigation,
// in the caller's tenant, are resolved; dry run changes nothing.
func TestResolveSourceMitigated_DB(t *testing.T) {
	f := newCoverageFixture(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: f.db})

	insert := func(tenant, asset shared.ID, tool, status, source string, lastSeen time.Time) (shared.ID, string) {
		id := shared.NewID()
		fp := "fp-" + id.String()
		f.exec(t, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, last_seen_tool, message, severity, fingerprint, status, last_seen_at)
			VALUES ($1, $2, $3, $4, $5, $5, 'm', 'high', $6, $7, $8)`,
			id, tenant, asset, source, tool, fp, status, lastSeen)
		return id, fp
	}
	now := time.Now().UTC()
	before := now.Add(-48 * time.Hour)

	open, openFP := insert(f.tenant, f.host, "tenable_sc", "new", "va", before)
	accepted, accFP := insert(f.tenant, f.host, "tenable_sc", "accepted", "va", before)
	fp1, fpFP := insert(f.tenant, f.host, "tenable_sc", "false_positive", "va", before)
	otherTool, otherToolFP := insert(f.tenant, f.host, "nuclei", "new", "dast", before)
	seenAfter, seenAfterFP := insert(f.tenant, f.host, "tenable_sc", "confirmed", "va", now)
	manual, manualFP := insert(f.tenant, f.host, "tenable_sc", "new", "manual", before)

	// Another tenant's finding under the same key must never be touched.
	otherTenant := shared.NewID()
	f.exec(t, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, otherTenant, "cov-o-"+otherTenant.String())
	t.Cleanup(func() { _, _ = f.db.ExecContext(ctx, "DELETE FROM tenants WHERE id = $1", otherTenant.String()) })
	otherAsset := shared.NewID()
	f.exec(t, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'h-o', 'host')`, otherAsset, otherTenant)
	foreign, _ := insert(otherTenant, otherAsset, "tenable_sc", "new", "va", before)

	mitigatedAt := now.Add(-time.Hour)
	items := []vulnerability.SourceMitigation{
		{Fingerprint: openFP, AssetID: f.host, MitigatedAt: mitigatedAt},
		{Fingerprint: accFP, AssetID: f.host, MitigatedAt: mitigatedAt},
		{Fingerprint: fpFP, AssetID: f.host, MitigatedAt: mitigatedAt},
		{Fingerprint: otherToolFP, AssetID: f.host, MitigatedAt: mitigatedAt},
		{Fingerprint: seenAfterFP, AssetID: f.host, MitigatedAt: mitigatedAt},
		{Fingerprint: manualFP, AssetID: f.host, MitigatedAt: mitigatedAt},
		// Right key, wrong asset: no match.
		{Fingerprint: openFP, AssetID: f.otherHost, MitigatedAt: mitigatedAt},
		// The foreign finding's key on this tenant's asset: no match.
		{Fingerprint: "fp-" + foreign.String(), AssetID: otherAsset, MitigatedAt: mitigatedAt},
	}

	ids, err := repo.ResolveSourceMitigated(ctx, f.tenant, "tenable_sc", items, true)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if len(ids) != 1 || ids[0] != open {
		t.Fatalf("dry run matched %v, want only %s", ids, open)
	}
	if got := f.status(t, open); got != "new" {
		t.Fatalf("dry run changed the status to %q", got)
	}

	ids, err = repo.ResolveSourceMitigated(ctx, f.tenant, "tenable_sc", items, false)
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if len(ids) != 1 || ids[0] != open {
		t.Fatalf("enforce resolved %v, want only %s", ids, open)
	}
	if got := f.status(t, open); got != "resolved" {
		t.Fatalf("open finding is %q, want resolved", got)
	}
	var method string
	if err := f.db.QueryRowContext(ctx, `SELECT COALESCE(resolution_method, '') FROM findings WHERE id = $1`, open.String()).Scan(&method); err != nil {
		t.Fatal(err)
	}
	if method != "source_mitigated" {
		t.Fatalf("resolution_method %q, want source_mitigated", method)
	}
	for id, want := range map[shared.ID]string{
		accepted: "accepted", fp1: "false_positive", otherTool: "new", seenAfter: "confirmed", manual: "new",
	} {
		if got := f.status(t, id); got != want {
			t.Errorf("finding %s is %q, want %q (must not be resolved)", id, got, want)
		}
	}
	var foreignStatus string
	if err := f.db.QueryRowContext(ctx, `SELECT status FROM findings WHERE id = $1`, foreign.String()).Scan(&foreignStatus); err != nil {
		t.Fatal(err)
	}
	if foreignStatus != "new" {
		t.Fatalf("another tenant's finding is %q, want open", foreignStatus)
	}

	// Nothing to do: no items, or no tool.
	if ids, err := repo.ResolveSourceMitigated(ctx, f.tenant, "", items, false); err != nil || len(ids) != 0 {
		t.Fatalf("empty tool: %v %v", ids, err)
	}
}
