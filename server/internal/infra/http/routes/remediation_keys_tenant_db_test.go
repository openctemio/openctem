package routes

// The remediation side table is joined to findings of the same tenant only.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestRemediationKeys_JoinStaysInTheTenant_DB(t *testing.T) {
	h := newDSHarness(t)
	ctx := context.Background()
	other := shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'rk-other', $2)`, other.String(), "rk-other-"+other.String()[28:])
	t.Cleanup(func() { h.exec(`DELETE FROM tenants WHERE id = $1`, other.String()) })
	asset, finding := shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, 'rk-asset', 'domain', 'public', 'high')`, asset.String(), other.String())
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, 'sca', 'rk', 'rk', 'high', $1::text, 'confirmed')`, finding.String(), other.String(), asset.String())
	// A key row filed under this tenant that points at the other tenant's
	// finding (a corrupt or forged row) must not count.
	h.exec(`INSERT INTO finding_remediation_keys (finding_id, tenant_id, remediation_key, title) VALUES ($1, $2, 'sca:rk-x', 'x')`,
		finding.String(), h.tenant.String())
	repo := postgres.NewFindingRemediationKeyRepository(&postgres.DB{DB: h.db})
	total, _, err := repo.CountByKey(ctx, h.tenant, "sca:rk-x", []string{"resolved"})
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 {
		t.Fatalf("a key row of this tenant counted another tenant's finding: total %d", total)
	}
	groups, err := repo.ListGroups(ctx, h.tenant, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range groups {
		if g.Key == "sca:rk-x" {
			t.Fatalf("group built from another tenant's finding: %+v", g)
		}
	}
}
