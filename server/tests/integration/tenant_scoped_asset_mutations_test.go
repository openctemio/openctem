package integration

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/sla"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// D-11 (research/14 SEC-15): these repository primitives used to update or
// delete by "WHERE id = $1" alone, trusting every caller to have checked the
// tenant first. Each case below plays the forgetful caller: tenant B presents
// tenant A's row id. The statement must change nothing and report not-found.

type assetMutationFixture struct {
	db           *sql.DB
	owner, other shared.ID
	exposureID   shared.ID
	slaID        shared.ID
	depID        shared.ID
	assetID      shared.ID
	componentID  shared.ID
	approvalID   shared.ID
}

func newAssetMutationFixture(t *testing.T) *assetMutationFixture {
	t.Helper()
	db := setupTestDB(t)
	f := &assetMutationFixture{
		db:          db,
		owner:       createTestTenant(t, db, "d11-asset-owner"),
		other:       createTestTenant(t, db, "d11-asset-other"),
		exposureID:  shared.NewID(),
		slaID:       shared.NewID(),
		depID:       shared.NewID(),
		assetID:     shared.NewID(),
		componentID: shared.NewID(),
		approvalID:  shared.NewID(),
	}
	t.Cleanup(func() {
		for _, id := range []shared.ID{f.owner, f.other} {
			_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, id.String())
		}
		_ = db.Close()
	})
	findingID := shared.NewID()
	stmts := []struct {
		q    string
		args []any
	}{
		{`INSERT INTO exposure_events (id, tenant_id, event_type, severity, state, title, fingerprint, source)
		  VALUES ($1, $2, 'credential_leaked', 'high', 'active', 'leak', $3, 'test')`,
			[]any{f.exposureID.String(), f.owner.String(), "fp-" + f.exposureID.String()}},
		{`INSERT INTO sla_policies (id, tenant_id, name) VALUES ($1, $2, 'owner policy')`,
			[]any{f.slaID.String(), f.owner.String()}},
		{`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'd11-repo', 'repository')`,
			[]any{f.assetID.String(), f.owner.String()}},
		{`INSERT INTO findings (id, tenant_id, source, tool_name, message, severity, fingerprint)
		  VALUES ($1, $2, 'sast', 'test', 'finding', 'high', $3)`,
			[]any{findingID.String(), f.owner.String(), "fp-" + findingID.String()}},
		{`INSERT INTO finding_status_approvals (id, tenant_id, finding_id, requested_status, status, version)
		  VALUES ($1, $2, $3, 'false_positive', 'pending', 1)`,
			[]any{f.approvalID.String(), f.owner.String(), findingID.String()}},
	}
	for _, s := range stmts {
		if _, err := db.Exec(s.q, s.args...); err != nil {
			t.Fatalf("seed: %v\n%s", err, s.q)
		}
	}
	return f
}

func (f *assetMutationFixture) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func TestD11_ExposureUpdateAndDeleteStayInTenant(t *testing.T) {
	f := newAssetMutationFixture(t)
	ctx := context.Background()
	repo := postgres.NewExposureRepository(&postgres.DB{DB: f.db})

	now := time.Now()
	forged := exposure.Reconstitute(f.exposureID, f.other, nil, exposure.EventTypeCredentialLeaked,
		exposure.SeverityHigh, exposure.StateResolved, "leak", "", nil, "fp-"+f.exposureID.String(), "test",
		now, now, &now, nil, "closed by another tenant", now, now)
	if err := repo.Update(ctx, forged); !errors.Is(err, exposure.ErrExposureEventNotFound) {
		t.Errorf("cross-tenant Update = %v, want not found", err)
	}
	if err := repo.Delete(ctx, f.other, f.exposureID); !errors.Is(err, exposure.ErrExposureEventNotFound) {
		t.Errorf("cross-tenant Delete = %v, want not found", err)
	}
	if n := f.count(t, `SELECT count(*) FROM exposure_events WHERE id = $1 AND state = 'active'`, f.exposureID.String()); n != 1 {
		t.Fatalf("owner's exposure changed by another tenant (rows still active: %d)", n)
	}
	if err := repo.Delete(ctx, f.owner, f.exposureID); err != nil {
		t.Fatalf("owner Delete: %v", err)
	}
}

func TestD11_SLAPolicyUpdateAndDeleteStayInTenant(t *testing.T) {
	f := newAssetMutationFixture(t)
	ctx := context.Background()
	repo := postgres.NewSLAPolicyRepository(&postgres.DB{DB: f.db})

	now := time.Now()
	forged := sla.Reconstitute(f.slaID, f.other, nil, "hijacked", "", false, 1, 1, 1, 1, 1, 80, false, nil, true, now, now)
	if err := repo.Update(ctx, forged); !errors.Is(err, sla.ErrNotFound) {
		t.Errorf("cross-tenant Update = %v, want not found", err)
	}
	if err := repo.Delete(ctx, f.other, f.slaID); !errors.Is(err, sla.ErrNotFound) {
		t.Errorf("cross-tenant Delete = %v, want not found", err)
	}
	if n := f.count(t, `SELECT count(*) FROM sla_policies WHERE id = $1 AND name = 'owner policy'`, f.slaID.String()); n != 1 {
		t.Fatalf("owner's SLA policy changed by another tenant")
	}
	if err := repo.Delete(ctx, f.owner, f.slaID); err != nil {
		t.Fatalf("owner Delete: %v", err)
	}
}

// Package links, edges and finding components stay in their tenant: another
// tenant cannot write a link on the owner's asset, cannot draw an edge
// between the owner's links, and cannot point its finding at the owner's
// private package version.
func TestD11_PackageLinksStayInTenant(t *testing.T) {
	f := newAssetMutationFixture(t)
	ctx := context.Background()
	productID, versionID := testdb.SeedPackageVersion(t, f.db, f.owner.String(), "pkg:npm/left-pad@1.0.0")
	link := testdb.SeedPackageLink(t, f.db, f.owner.String(), f.assetID.String(), productID, versionID, "package.json", "direct")
	otherProduct, otherVersion := testdb.SeedPackageVersion(t, f.db, f.owner.String(), "pkg:npm/right-pad@1.0.0")
	link2 := testdb.SeedPackageLink(t, f.db, f.owner.String(), f.assetID.String(), otherProduct, otherVersion, "package.json", "transitive")

	writer := postgres.NewSoftwarePackageWriter(&postgres.DB{DB: f.db})
	purl, err := software.ParsePURL("pkg:npm/evil@6.6.6")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WritePackages(ctx, f.other, software.PackageSnapshot{
		AssetID: f.assetID, Packages: []software.PackageNode{{Ref: "e", PURL: purl, Relationship: "direct"}}, Replace: true,
	}); err == nil {
		t.Error("another tenant wrote a package link on the owner's asset")
	}
	if _, err := f.db.Exec(`INSERT INTO asset_software_edges (tenant_id, asset_id, parent_id, child_id) VALUES ($1, $2, $3, $4)`,
		f.other.String(), f.assetID.String(), link, link2); err == nil {
		t.Error("another tenant drew an edge between the owner's links")
	}
	findingID := shared.NewID()
	if _, err := f.db.Exec(`INSERT INTO findings (id, tenant_id, source, tool_name, message, severity, fingerprint, component_id)
		VALUES ($1, $2, 'sca', 'test', 'x', 'high', $3, $4)`, findingID.String(), f.other.String(), "fp-"+findingID.String(), versionID); err == nil {
		t.Error("another tenant's finding points at the owner's private package version")
	}
	if n := f.count(t, `SELECT count(*) FROM asset_software WHERE asset_id = $1 AND source = 'package'`, f.assetID.String()); n != 2 {
		t.Fatalf("owner's links changed: %d", n)
	}
}

func TestD11_FindingApprovalUpdateStaysInTenant(t *testing.T) {
	f := newAssetMutationFixture(t)
	ctx := context.Background()
	repo := postgres.NewFindingApprovalRepository(&postgres.DB{DB: f.db})

	now := time.Now()
	forged := &vulnerability.Approval{
		ID: f.approvalID, TenantID: f.other, Status: vulnerability.ApprovalStatusApproved,
		ApprovedAt: &now, Version: 2,
	}
	if err := repo.Update(ctx, forged); err == nil {
		t.Error("cross-tenant approval Update succeeded")
	}
	if n := f.count(t, `SELECT count(*) FROM finding_status_approvals WHERE id = $1 AND status = 'pending' AND version = 1`, f.approvalID.String()); n != 1 {
		t.Fatalf("owner's approval changed by another tenant")
	}
	forged.TenantID = f.owner
	if err := repo.Update(ctx, forged); err != nil {
		t.Fatalf("owner Update: %v", err)
	}
}
