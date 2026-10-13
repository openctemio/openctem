package sensorgrant_test

// Grant suggestion against a migrated database: the usage read is tenant-
// and sensor-scoped, the suggestion is never wider than the current grant,
// applying needs a grant permission and step-up, a stale view writes
// nothing, and another tenant reads not found.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/sensorgrant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type gate struct{ err error }

func (g gate) RequireRecentAuth(context.Context, string) error { return g.err }

// legacy makes a sensor's grant the legacy broad grant, trusted.
func (f *fixture) legacy(tid, sid shared.ID) {
	f.exec(`UPDATE sensors SET trust_level = 'trusted' WHERE id = $1`, sid.String())
	f.exec(`UPDATE sensor_grants SET profile = 'legacy-broad', job_types = NULL, tier_ceiling = 2, target_network = 'any',
		allow_credentials = TRUE, allow_push_ingest = TRUE, remote_actions = ARRAY['diagnostics','rotate_key','update']
		WHERE sensor_id = $1 AND tenant_id = $2`, sid.String(), tid.String())
}

func (f *fixture) job(tid, sid shared.ID, payload string, age time.Duration) {
	f.exec(`INSERT INTO commands (tenant_id, sensor_id, type, payload, status, created_at)
		VALUES ($1, $2, 'scan', $3::jsonb, 'completed', NOW() - $4::interval)`,
		tid.String(), sid.String(), payload, age.String())
}

func (f *fixture) suggestSvc(g shared.RecentAuthGate) *sensorgrant.Service {
	pg := f.pg
	svc := sensorgrant.NewService(f.grants, postgres.NewSensorRepository(pg), logger.NewNop())
	svc.SetZoneChecker(f.grants)
	svc.SetUsage(f.grants, postgres.NewSensorRepository(pg))
	if g != nil {
		svc.SetStepUpGate(g)
	}
	return svc
}

func TestGrantSuggestion_ApplyNarrows_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tid, uid := f.org()
	otherTenant, otherUser := f.org()
	sid := f.sensor(tid, []string{"httpx", "subfinder"}, nil)
	f.legacy(tid, sid)
	f.job(tid, sid, `{"scanner":"httpx","targets":["https://example.com"]}`, time.Hour)
	f.job(tid, sid, `{"scanner":"subfinder","targets":["example.com"]}`, 24*time.Hour)
	// Older than the window: a private target that must not count.
	f.job(tid, sid, `{"scanner":"httpx","targets":["10.0.0.1"]}`, 40*24*time.Hour)

	svc := f.suggestSvc(gate{})
	v, err := svc.Suggest(ctx, tid, sid)
	if err != nil {
		t.Fatalf("suggest: %v", err)
	}
	if !v.Available || v.Profile != sensordom.ProfileEASMExternal || v.CurrentProfile != sensordom.ProfileLegacyBroad ||
		v.Usage.JobCount != 2 || v.Usage.PrivateTargets || !v.Usage.PublicTargets {
		t.Fatalf("suggestion: %+v", v)
	}

	// Cross-tenant: another organization sees and applies nothing.
	if _, err := svc.Suggest(ctx, otherTenant, sid); !errors.Is(err, sensorgrant.ErrNotFound) {
		t.Fatalf("cross-tenant suggest: %v", err)
	}
	if _, err := svc.ApplySuggestion(ctx, admin(otherTenant, otherUser), sid, v.CurrentVersion, v.Profile); !errors.Is(err, sensorgrant.ErrNotFound) {
		t.Fatalf("cross-tenant apply: %v", err)
	}
	// A member without a grant permission cannot apply.
	if _, err := svc.ApplySuggestion(ctx, sensorgrant.Actor{TenantID: tid, UserID: uid}, sid, v.CurrentVersion, v.Profile); !errors.Is(err, sensorgrant.ErrNarrowForbidden) {
		t.Fatalf("no permission: %v", err)
	}
	// Step-up: required (the gate's refusal is returned), and fail closed
	// when not wired.
	stepErr := errors.New("step up")
	if _, err := f.suggestSvc(gate{err: stepErr}).ApplySuggestion(ctx, admin(tid, uid), sid, v.CurrentVersion, v.Profile); !errors.Is(err, stepErr) {
		t.Fatalf("no step-up: %v", err)
	}
	if _, err := f.suggestSvc(nil).ApplySuggestion(ctx, admin(tid, uid), sid, v.CurrentVersion, v.Profile); !errors.Is(err, sensorgrant.ErrStepUpUnavailable) {
		t.Fatalf("step-up not wired: %v", err)
	}
	// A stale view writes nothing.
	if _, err := svc.ApplySuggestion(ctx, admin(tid, uid), sid, v.CurrentVersion, sensordom.ProfileInternalScanner); !errors.Is(err, sensorgrant.ErrSuggestionChanged) {
		t.Fatalf("other profile: %v", err)
	}
	if _, err := svc.ApplySuggestion(ctx, admin(tid, uid), sid, v.CurrentVersion+1, v.Profile); !errors.Is(err, sensorgrant.ErrVersionConflict) {
		t.Fatalf("stale version: %v", err)
	}
	before, _ := f.grants.Get(ctx, tid, sid)
	if before.Profile != sensordom.ProfileLegacyBroad {
		t.Fatalf("refused applies changed the grant: %+v", before)
	}

	// A narrow-only administrator applies it: narrowing, never widening.
	g, err := svc.ApplySuggestion(ctx, narrowOnly(tid, uid), sid, v.CurrentVersion, v.Profile)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	stored, _ := f.grants.Get(ctx, tid, sid)
	if stored.Profile != sensordom.ProfileEASMExternal || stored.Version != before.Version+1 || stored.TrustLevel != sensordom.TrustTrusted ||
		stored.TargetNetwork != sensordom.TargetNetworkPublic || g.Version != stored.Version {
		t.Fatalf("stored: %+v", stored)
	}
	if w := sensordom.Widened(*before, *stored); len(w) > 0 {
		t.Fatalf("apply widened %v", w)
	}
	// Applied: nothing narrower is left to suggest.
	if v2, err := svc.Suggest(ctx, tid, sid); err != nil || v2.Available || v2.Reason != sensordom.SuggestReasonAlreadyNarrow {
		t.Fatalf("after apply: %+v %v", v2, err)
	}
}

func TestGrantSuggestion_UsageScoped_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tid, _ := f.org()
	otherTenant, _ := f.org()
	sid := f.sensor(tid, []string{"httpx"}, nil)
	other := f.sensor(otherTenant, []string{"httpx"}, nil)
	f.legacy(tid, sid)
	f.job(tid, sid, `{"scanner":"httpx","targets":["https://example.com"]}`, time.Hour)
	// Another sensor's private jobs, in another tenant, do not count.
	f.job(otherTenant, other, `{"scanner":"httpx","targets":["10.0.0.1"]}`, time.Hour)
	// Results the sensor pushed without a job need push ingest.
	f.exec(`INSERT INTO sensor_result_quarantine (id, tenant_id, sensor_id, protocol, route, reason)
		VALUES ($1, $2, $3, 'v2', 'results', 'test')`, shared.NewID().String(), otherTenant.String(), other.String())

	u, err := f.grants.GrantUsage(ctx, tid, sid, time.Now().Add(-sensorgrant.SuggestWindow), 10)
	if err != nil || len(u.Jobs) != 1 || u.PushIngest || !u.Complete {
		t.Fatalf("usage: %+v %v", u, err)
	}
	// Too many distinct jobs: incomplete, no suggestion.
	f.job(tid, sid, `{"scanner":"httpx","targets":["https://a.example.com"]}`, time.Hour)
	if u, _ := f.grants.GrantUsage(ctx, tid, sid, time.Now().Add(-sensorgrant.SuggestWindow), 1); u.Complete {
		t.Fatalf("truncated usage reads complete: %+v", u)
	}
	// Push ingest of the sensor itself.
	f.exec(`INSERT INTO sensor_result_quarantine (id, tenant_id, sensor_id, protocol, route, reason)
		VALUES ($1, $2, $3, 'v2', 'results', 'test')`, shared.NewID().String(), tid.String(), sid.String())
	if u, _ := f.grants.GrantUsage(ctx, tid, sid, time.Now().Add(-sensorgrant.SuggestWindow), 10); !u.PushIngest {
		t.Fatalf("push not seen: %+v", u)
	}
	f.exec(`DELETE FROM sensor_result_quarantine WHERE tenant_id IN ($1, $2)`, tid.String(), otherTenant.String())
}

// A new EASM sensor gets the public-only profile from the insert trigger.
func TestGrant_DefaultEASM_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tid, _ := f.org()
	id := shared.NewID()
	f.exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, api_key_hash, api_key_prefix,
		execution_mode, max_concurrent_jobs, current_jobs)
		VALUES ($1, $2, $3, 'sensor', 'active', 'online', $4, $5, 'daemon', 5, 0)`,
		id.String(), tid.String(), "grant-easm-"+id.String(), "hash-"+id.String(), id.String()[:8])
	g, err := f.grants.Get(ctx, tid, id)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := sensordom.NewGrantFromProfile(tid, id, sensordom.DefaultProfileFor(sensordom.SensorTypeEASM), nil)
	_ = want.Normalize()
	if g.Profile != sensordom.ProfileEASMExternal || g.TargetNetwork != sensordom.TargetNetworkPublic ||
		g.TierCeiling != sensordom.TierActive || g.AllowPushIngest || g.TrustLevel != sensordom.TrustNew ||
		len(sensordom.Changed(*want, *g)) != 0 {
		t.Fatalf("EASM default: %+v", g)
	}
}
