package sensorpairing_test

// The grant a pairing approval creates (RFC-052 §4.5, §4.6, §5): the chosen
// profile at trust level New, in the approval's transaction; the profile an
// expectation named; legacy-broad never; a re-paired sensor keeps its grant
// and goes back to New.

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/sensorgrant"
	"github.com/openctemio/openctem/api/internal/app/sensorpairing"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func (f *fixture) withGrants() *postgres.SensorGrantRepository {
	pg := &postgres.DB{DB: f.db}
	repo := postgres.NewSensorGrantRepository(pg)
	f.svc.SetApprovalHook(sensorgrant.NewService(repo, postgres.NewSensorRepository(pg), logger.NewNop()))
	return repo
}

func (f *fixture) grant(repo *postgres.SensorGrantRepository, tenantID shared.ID, sensorID string) *sensordom.Grant {
	f.t.Helper()
	sid, _ := shared.IDFromString(sensorID)
	g, err := repo.Get(context.Background(), tenantID, sid)
	if err != nil {
		f.t.Fatalf("grant: %v", err)
	}
	return g
}

func TestPairing_ApprovalCreatesGrant_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	grants := f.withGrants()
	a := f.org("org-grant")

	// Forward mode with a chosen profile.
	s := newSensor(31)
	f.start(s, "", "")
	f.reveal(s)
	id, _ := shared.IDFromString(s.resp.PairingID)
	legacy := approve(a, s.resp.UserCode)
	legacy.Profile = sensordom.ProfileLegacyBroad
	if _, err := f.approveP(ctx, a, id, legacy); !errors.Is(err, sensorpairing.ErrInvalid) {
		t.Fatalf("legacy-broad chosen at approval: %v", err)
	}
	in := approve(a, s.resp.UserCode)
	in.Profile = sensordom.ProfileEASMExternal
	if _, err := f.approveP(ctx, a, id, in); err != nil {
		t.Fatalf("approve: %v", err)
	}
	st := f.status(s)
	g := f.grant(grants, a.TenantID, st.Identity.SensorID)
	if g.Profile != sensordom.ProfileEASMExternal || g.TrustLevel != sensordom.TrustNew || g.UpdatedBy == nil || *g.UpdatedBy != a.UserID {
		t.Fatalf("grant after approval: %+v", g)
	}

	// Re-pair returns the sensor to New even after a promotion.
	if _, err := f.confirm(s, st.Identity); err != nil {
		t.Fatal(err)
	}
	f.exec(`UPDATE sensors SET trust_level = 'trusted' WHERE id = $1`, st.Identity.SensorID)
	second := newSensor(32)
	f.start(second, "", st.Identity.SensorID)
	f.reveal(second)
	rid, _ := shared.IDFromString(second.resp.PairingID)
	rin := approve(a, second.resp.UserCode)
	rin.RepairSensorID = st.Identity.SensorID
	rin.Profile = sensordom.ProfileCollector // ignored: a re-pair keeps the grant
	if _, err := f.approveP(ctx, a, rid, rin); err != nil {
		t.Fatalf("re-pair approve: %v", err)
	}
	if g := f.grant(grants, a.TenantID, st.Identity.SensorID); g.TrustLevel != sensordom.TrustNew || g.Profile != sensordom.ProfileEASMExternal {
		t.Fatalf("grant after re-pair (kept, trust New): %+v", g)
	}

	// Reverse mode: the expectation's profile applies when the approval
	// names none.
	exp, err := f.svc.Expect(ctx, a, sensorpairing.ExpectInput{Name: "ci-box", Profile: sensordom.ProfileCIRunner})
	if err != nil {
		t.Fatalf("expect: %v", err)
	}
	r := newSensor(33)
	f.start(r, exp.Code, "")
	f.reveal(r)
	eid, _ := shared.IDFromString(exp.ID)
	if _, err := f.approveP(ctx, a, eid, approve(a, "")); err != nil {
		t.Fatalf("approve expectation: %v", err)
	}
	if g := f.grant(grants, a.TenantID, f.status(r).Identity.SensorID); g.Profile != sensordom.ProfileCIRunner || g.TargetNetwork != sensordom.TargetNetworkNone {
		t.Fatalf("expectation profile not used: %+v", g)
	}
}

// A collector approved without a chosen profile gets the collector profile
// (push ingest in the grant), still at trust level New.
func TestPairing_CollectorDefaultProfile_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	grants := f.withGrants()
	a := f.org("org-grant-collector")

	s := newSensor(41)
	f.start(s, "", "")
	f.reveal(s)
	id, _ := shared.IDFromString(s.resp.PairingID)
	in := approve(a, s.resp.UserCode)
	in.Type = sensordom.SensorTypeCollector
	if _, err := f.approveP(ctx, a, id, in); err != nil {
		t.Fatalf("approve: %v", err)
	}
	g := f.grant(grants, a.TenantID, f.status(s).Identity.SensorID)
	if g.Profile != sensordom.ProfileCollector || g.TrustLevel != sensordom.TrustNew || !g.AllowPushIngest || g.Effective().AllowPushIngest {
		t.Fatalf("collector grant after approval: %+v", g)
	}
}
