package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// The findings list filtered by a remediation key is the set the key
// repository counts for a keyed campaign: same tenant, same key, pentest
// findings left out. A keyed campaign page therefore lists what it counts.
func TestFindingFilter_RemediationKeyMatchesKeyCount_DB(t *testing.T) {
	ctx := context.Background()
	sqldb := openGroupsDB(t)
	db := &DB{DB: sqldb}
	findings := NewFindingRepository(db)
	keys := NewFindingRemediationKeyRepository(db)

	tenant, other := seedTestTenant(ctx, t, sqldb), seedTestTenant(ctx, t, sqldb)
	asset, otherAsset := seedOwnedAsset(ctx, t, sqldb, tenant, nil), seedOwnedAsset(ctx, t, sqldb, other, nil)
	const key = "pkg:npm/lodash@4.17.20"

	seed := func(tid, aid shared.ID, source, status, k string) shared.ID {
		t.Helper()
		id := shared.NewID()
		if _, err := sqldb.ExecContext(ctx, `
			INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1, $2, $3, $4, 'test', 'msg', 'high', $5, $6)`,
			id.String(), tid.String(), aid.String(), source, id.String(), status); err != nil {
			t.Fatalf("seed finding: %v", err)
		}
		if k != "" {
			if _, err := sqldb.ExecContext(ctx, `
				INSERT INTO finding_remediation_keys (finding_id, tenant_id, remediation_key) VALUES ($1, $2, $3)`,
				id.String(), tid.String(), k); err != nil {
				t.Fatalf("seed key: %v", err)
			}
		}
		return id
	}
	open := seed(tenant, asset, "sca", "new", key)
	closed := seed(tenant, asset, "sca", "resolved", key)
	seed(tenant, asset, "pentest", "new", key)           // pentest: not in a solution family
	seed(tenant, asset, "sca", "new", "pkg:npm/other@1") // another key
	seed(other, otherAsset, "sca", "new", key)           // another tenant

	k := key
	filter := vulnerability.NewFindingFilter().WithTenantID(tenant)
	filter.RemediationKey = &k
	page, err := findings.List(ctx, filter, vulnerability.NewFindingListOptions(), pagination.New(1, 50))
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	total, _, err := keys.CountByKey(ctx, tenant, key, []string{"resolved"})
	if err != nil {
		t.Fatalf("CountByKey: %v", err)
	}
	if page.Total != total || total != 2 {
		t.Fatalf("list total %d, key count %d, want 2 and equal", page.Total, total)
	}
	got := map[string]bool{}
	for _, f := range page.Data {
		got[f.ID().String()] = true
	}
	if !got[open.String()] || !got[closed.String()] {
		t.Fatalf("list %v, want the open and resolved findings of the key", got)
	}
}
