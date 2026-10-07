package retest_test

// The active-probe gate on every validate-command path, against a migrated
// Postgres with the production gate (scope exclusions, attribution, scan
// zones): a retest, a validation re-check, a simulation safe-check and the
// proof-of-fix fallback all refuse an excluded target, a private address
// outside every zone and an asset whose ownership is not confirmed, and no
// command reaches a sensor. Another tenant's exclusions, zones and
// attribution never apply. Architecture: docs/architecture/active-probe-gate.md.

import (
	"context"
	"errors"
	"testing"

	retestapp "github.com/openctemio/openctem/api/internal/app/retest"
	"github.com/openctemio/openctem/api/internal/app/validation"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	retestdom "github.com/openctemio/openctem/api/pkg/domain/retest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func (fx *fixture) newTypedAsset(name, typ string) shared.ID {
	id := shared.NewID()
	fx.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, $4, 'active')`,
		id.String(), fx.tenant.String(), name, typ)
	return id
}

func (fx *fixture) excludeDomain(pattern string) {
	fx.exec(`INSERT INTO scope_exclusions (tenant_id, exclusion_type, pattern, reason, status, approved_by, approved_at, created_by)
		VALUES ($1, 'domain', $2, 'test', 'active', 'approver', NOW(), 'requester')`, fx.tenant.String(), pattern)
}

func (fx *fixture) attribution(asset shared.ID, state string) {
	fx.exec(`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1, $2, $3, 50)`,
		asset.String(), fx.tenant.String(), state)
}

func (fx *fixture) zone(name, cidr string) {
	fx.exec(`INSERT INTO scan_zones (tenant_id, name, ranges) VALUES ($1, $2, ARRAY[$3]::cidr[])`, fx.tenant.String(), name, cidr)
}

func (fx *fixture) count(q string) int {
	fx.t.Helper()
	var n int
	if err := fx.db.QueryRow(q, fx.tenant.String()).Scan(&n); err != nil {
		fx.t.Fatal(err)
	}
	return n
}

func (fx *fixture) commandCount() int {
	return fx.count(`SELECT COUNT(*) FROM commands WHERE tenant_id = $1`)
}

func (fx *fixture) runService() *validation.RunService {
	return validation.NewRunService(postgres.NewFindingRepository(fx.pg), postgres.NewAssetRepository(fx.pg),
		validation.NewCommandDispatcher(postgres.NewCommandRepository(fx.pg), fx.gate(), logger.NewNop()),
		validation.DefaultSelector{}, []validation.ExecutorKind{validation.KindSafeCheck}, logger.NewNop())
}

// refusedCase is one target the gate must refuse, set up on a fixture.
type refusedCase struct {
	name  string
	setup func(fx *fixture) shared.ID // returns the asset
}

var refusedCases = []refusedCase{
	{"excluded", func(fx *fixture) shared.ID {
		fx.excludeDomain("shop.example.com")
		return fx.asset
	}},
	{"private address outside every zone", func(fx *fixture) shared.ID {
		fx.zone("dc-a", "10.1.0.0/16")
		return fx.newTypedAsset("10.9.0.5", "ip_address")
	}},
	{"private address, tenant without zones", func(fx *fixture) shared.ID {
		return fx.newTypedAsset("10.9.0.6", "ip_address")
	}},
	{"ownership not confirmed", func(fx *fixture) shared.ID {
		fx.attribution(fx.asset, "needs_review")
		return fx.asset
	}},
	{"ownership rejected", func(fx *fixture) shared.ID {
		fx.attribution(fx.asset, "rejected")
		return fx.asset
	}},
}

func TestGateDB_RetestRefusedAndNothingDispatched(t *testing.T) {
	for _, tc := range refusedCases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			asset := tc.setup(fx)
			f := fx.newFinding(asset, "confirmed", "tpl-gate")
			user := fx.user
			_, err := fx.service().Request(context.Background(), retestapp.RequestInput{
				TenantID: fx.tenant, FindingID: f, Trigger: retestdom.TriggerManual, RequestedBy: &user,
			})
			if !errors.Is(err, validation.ErrTargetRefused) || !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("err = %v, want ErrTargetRefused (400)", err)
			}
			if errors.Is(err, retestdom.ErrNotEligible) {
				t.Fatal("a gate refusal must not read as ineligible: proof-of-fix would fall back to another probe")
			}
			if n := fx.commandCount(); n != 0 {
				t.Fatalf("%d command(s) queued for a refused target", n)
			}
			if n := fx.count(`SELECT COUNT(*) FROM finding_retests WHERE tenant_id = $1`); n != 0 {
				t.Fatalf("%d retest row(s) for a refused target; the slot must stay free", n)
			}
		})
	}
}

// L-08: proof-of-fix must not fall back to a plain re-check of a target the
// gate refused, and the plain re-check refuses it on its own too.
func TestGateDB_ProofOfFixFallbackRefused(t *testing.T) {
	for _, tc := range refusedCases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			asset := tc.setup(fx)
			fallback := &fallbackValidator{}
			pof := retestapp.NewProofOfFix(fx.service(), fallback)

			nuclei := fx.newFinding(asset, "fix_applied", "tpl-pof-gate")
			if _, err := pof.ValidateFinding(context.Background(), fx.tenant, nuclei); !errors.Is(err, validation.ErrTargetRefused) {
				t.Fatalf("proof of fix: err = %v, want ErrTargetRefused", err)
			}
			if fallback.calls != 0 {
				t.Fatal("a refused retest fell back to another probe of the same target")
			}

			// A finding with no deterministic re-check goes to the real
			// fallback, which runs the same gate.
			trivy := fx.newFinding(asset, "fix_applied", "CVE-2024-0002")
			fx.exec(`UPDATE findings SET tool_name = 'trivy' WHERE id = $1`, trivy.String())
			real := retestapp.NewProofOfFix(fx.service(), fx.runService())
			if _, err := real.ValidateFinding(context.Background(), fx.tenant, trivy); !errors.Is(err, validation.ErrTargetRefused) {
				t.Fatalf("fallback re-check: err = %v, want ErrTargetRefused", err)
			}
			if n := fx.commandCount(); n != 0 {
				t.Fatalf("%d command(s) queued for a refused target", n)
			}
		})
	}
}

// The validation re-check (POST /findings/{id}/validate) and the attack
// simulation safe-check refuse the same targets.
func TestGateDB_ValidationAndSimulationRefused(t *testing.T) {
	for _, tc := range refusedCases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			asset := tc.setup(fx)
			run := fx.runService()
			f := fx.newFinding(asset, "confirmed", "tpl-validate")
			if _, err := run.ValidateFinding(context.Background(), fx.tenant, f); !errors.Is(err, validation.ErrTargetRefused) {
				t.Fatalf("validate: err = %v, want ErrTargetRefused", err)
			}
			if _, err := run.DispatchSimulationCheck(context.Background(), fx.tenant, shared.NewID(), asset, "T1046"); !errors.Is(err, validation.ErrTargetRefused) {
				t.Fatalf("simulation: err = %v, want ErrTargetRefused", err)
			}
			if n := fx.commandCount(); n != 0 {
				t.Fatalf("%d command(s) queued for a refused target", n)
			}
		})
	}
}

// A private target inside a zone is probed, and only the zone's sensors may
// claim the command.
func TestGateDB_ZonedTargetIsPinnedToItsZone(t *testing.T) {
	fx := newFixture(t)
	fx.zone("dc-a", "10.1.0.0/16")
	fx.exec(`INSERT INTO sensors (tenant_id, name, type, status, api_key_hash, api_key_prefix)
		VALUES ($1, 'zone-sensor', 'worker', 'active', md5(gen_random_uuid()::text), 'octs_test')`, fx.tenant.String())
	fx.exec(`INSERT INTO scan_zone_sensors (zone_id, sensor_id, tenant_id)
		SELECT z.id, s.id, z.tenant_id FROM scan_zones z JOIN sensors s ON s.tenant_id = z.tenant_id WHERE z.tenant_id = $1`, fx.tenant.String())
	asset := fx.newTypedAsset("10.1.2.3", "ip_address")
	f := fx.newFinding(asset, "confirmed", "tpl-zone")
	if _, err := fx.runService().ValidateFinding(context.Background(), fx.tenant, f); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if n := fx.count(`SELECT COUNT(*) FROM commands c JOIN scan_zones z ON z.id = c.scan_zone_id WHERE c.tenant_id = $1 AND z.name = 'dc-a'`); n != 1 {
		t.Fatalf("%d command(s) pinned to the zone, want 1", n)
	}
}

// Cross-tenant: tenant B's exclusion of the same name, B's unconfirmed asset
// of the same name and B's zones do not refuse tenant A's probe; A's do not
// refuse B's.
func TestGateDB_OtherTenantsPolicyDoesNotApply(t *testing.T) {
	a := newFixture(t)
	b := newFixture(t)
	b.excludeDomain("shop.example.com")
	b.attribution(b.asset, "rejected")
	b.zone("b-zone", "10.1.0.0/16")
	a.excludeDomain("other.example.com")

	fa := a.newFinding(a.asset, "confirmed", "tpl-a")
	if _, err := a.runService().ValidateFinding(context.Background(), a.tenant, fa); err != nil {
		t.Fatalf("tenant A probe refused by tenant B policy: %v", err)
	}
	if n := a.commandCount(); n != 1 {
		t.Fatalf("tenant A commands = %d, want 1", n)
	}
	// B's own asset stays refused (its own rejected attribution), and A's
	// zone-less tenant does not admit B's private asset through B's zone
	// for A: a 10.1 address in A is refused.
	fb := b.newFinding(b.asset, "confirmed", "tpl-b")
	if _, err := b.runService().ValidateFinding(context.Background(), b.tenant, fb); !errors.Is(err, validation.ErrTargetRefused) {
		t.Fatalf("tenant B own policy: err = %v, want ErrTargetRefused", err)
	}
	priv := a.newTypedAsset("10.1.2.3", "ip_address")
	fp := a.newFinding(priv, "confirmed", "tpl-a-priv")
	if _, err := a.runService().ValidateFinding(context.Background(), a.tenant, fp); !errors.Is(err, validation.ErrTargetRefused) {
		t.Fatalf("tenant A probing a private address covered only by tenant B's zone: err = %v", err)
	}
	if n := b.commandCount(); n != 0 {
		t.Fatalf("tenant B commands = %d, want 0", n)
	}
	// And an asset id of another tenant is not found, never probed.
	if _, err := a.runService().DispatchSimulationCheck(context.Background(), a.tenant, shared.NewID(), b.asset, "T1046"); err == nil {
		t.Fatal("tenant A dispatched a probe at tenant B's asset")
	}
	if n := a.commandCount(); n != 1 {
		t.Fatalf("tenant A commands = %d, want still 1", n)
	}
}

// An internet-facing asset with no attribution record outside every scope
// target and seed is not probed (RFC-036 §6.3, research/22b S1). A person
// confirming it records ownership but does not authorize the probe (RFC-054
// §4.2): it is probed once a scope target covers it.
func TestGateDB_UnattributedAssetIsNotProbed(t *testing.T) {
	fx := newFixture(t)
	asset := fx.newAsset("shop.unlisted.net")
	f := fx.newFinding(asset, "confirmed", "tpl-unlisted")
	if _, err := fx.runService().ValidateFinding(context.Background(), fx.tenant, f); err == nil {
		t.Fatal("an unattributed asset was probed")
	}
	if n := fx.commandCount(); n != 0 {
		t.Fatalf("%d command(s) created for an unattributed asset", n)
	}
	fx.exec(`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence, decided_at) VALUES ($1, $2, 'confirmed', 0, now())`,
		asset.String(), fx.tenant.String())
	if _, err := fx.runService().ValidateFinding(context.Background(), fx.tenant, f); err == nil {
		t.Fatal("a confirmed asset outside every scope entry was probed (ownership is not authority)")
	}
	if n := fx.commandCount(); n != 0 {
		t.Fatalf("%d command(s) created for a confirmed asset outside scope", n)
	}
	fx.exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, status) VALUES ($1, 'domain', '*.unlisted.net', 'active')`,
		fx.tenant.String())
	if _, err := fx.runService().ValidateFinding(context.Background(), fx.tenant, f); err != nil {
		t.Fatalf("a confirmed asset inside a scope target was refused: %v", err)
	}
}
