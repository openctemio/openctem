package sensorpairing_test

// The approval screen's context and its binding
// (docs/rfcs/RFC-052-sensor-pairing-and-authorization.md §4.5, threats 2,
// 4 and 22-24): the review names the organization the sensor joins and the
// approval must name the same one; a request no organization claimed is
// rejected only with its code; the failed lookup that locks a user's
// lookups is audited.

import (
	"context"
	"errors"
	"net"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/sensorpairing"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorproto/pairing"
)

func (f *fixture) withTenantsAndAudit() {
	db := &postgres.DB{DB: f.db}
	f.svc.SetTenants(postgres.NewTenantRepository(db))
	f.svc.SetAudit(auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop()))
}

func (f *fixture) auditCount(tenant shared.ID, action string) int {
	f.t.Helper()
	var n int
	if err := f.db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = $2`, tenant.String(), action).Scan(&n); err != nil {
		f.t.Fatalf("count audit: %v", err)
	}
	return n
}

func (f *fixture) cleanAudit(tenants ...shared.ID) {
	f.t.Cleanup(func() {
		for _, id := range tenants {
			_, _ = f.db.ExecContext(context.Background(), `DELETE FROM audit_logs WHERE tenant_id = $1`, id.String())
		}
	})
}

func TestPairing_ReviewNamesAndBindsTheOrganization_DB(t *testing.T) {
	f := newFixture(t)
	f.withTenantsAndAudit()
	ctx := context.Background()
	a, b := f.org("org-a"), f.org("org-b")
	f.cleanAudit(a.TenantID, b.TenantID)

	s := newSensor(61)
	f.start(s, "", "")
	f.reveal(s)
	id, _ := shared.IDFromString(s.resp.PairingID)

	v, err := f.svc.Lookup(ctx, a, s.resp.UserCode)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if v.OrganizationID != a.TenantID.String() || v.OrganizationName != "org-a" {
		t.Fatalf("organization on the review: %q %q", v.OrganizationID, v.OrganizationName)
	}
	if v.ApproverIP != a.IP || v.SourceIP != "203.0.113.9" || v.SourceNetwork != "public" {
		t.Fatalf("addresses on the review: approver %q source %q network %q", v.ApproverIP, v.SourceIP, v.SourceNetwork)
	}
	// The same code looked up in another organization names that one.
	if vb, err := f.svc.Lookup(ctx, b, s.resp.UserCode); err != nil || vb.OrganizationID != b.TenantID.String() {
		t.Fatalf("lookup in org-b: %v %+v", err, vb)
	}

	// The approver switched to org-b after reviewing in org-a: refused
	// before step-up, nothing written.
	f.stepUp.ok = false // a refused approval must not reach step-up
	for _, named := range []string{a.TenantID.String(), "", "not-an-id"} {
		in := approve(b, s.resp.UserCode)
		in.OrganizationID = named
		if _, err := f.svc.Approve(ctx, b, id, in); !errors.Is(err, sensorpairing.ErrOrganizationMismatch) {
			t.Fatalf("approval naming %q in org-b: %v", named, err)
		}
	}
	f.stepUp.ok = true
	if f.auditCount(b.TenantID, "sensor.pairing_approved") != 3 {
		t.Fatalf("refused approvals not audited: %d", f.auditCount(b.TenantID, "sensor.pairing_approved"))
	}
	if st := f.status(s); st.Status != pairing.StatusPending || st.Identity != nil {
		t.Fatalf("a refused approval changed the request: %+v", st)
	}
	// Named and session organization agree: the sensor joins org-a.
	if _, err := f.svc.Approve(ctx, a, id, approve(a, s.resp.UserCode)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if st := f.status(s); st.Identity == nil || st.Identity.TenantID != a.TenantID.String() {
		t.Fatalf("approved into the wrong organization: %+v", st.Identity)
	}
}

func TestPairing_RejectOfAnUnclaimedRequestNeedsTheCode_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a, b := f.org("org-a"), f.org("org-b")

	s := newSensor(62)
	f.start(s, "", "")
	f.reveal(s)
	id, _ := shared.IDFromString(s.resp.PairingID)

	// The id alone, a wrong code or a malformed one: the uniform 404, and
	// the request stays open.
	for _, code := range []string{"", "AAAA-AAAA", "nope"} {
		if err := f.svc.Deny(ctx, b, id, code); !errors.Is(err, sensorpairing.ErrNotFound) {
			t.Fatalf("deny with code %q: %v", code, err)
		}
	}
	if st := f.status(s); st.Status != pairing.StatusPending {
		t.Fatalf("status after refused denials: %q", st.Status)
	}
	if _, err := f.svc.Lookup(ctx, a, s.resp.UserCode); err != nil {
		t.Fatalf("the request is no longer open: %v", err)
	}
	// With the code it is rejected, and an expectation of the organization
	// still needs no code.
	if err := f.svc.Deny(ctx, a, id, s.resp.UserCode); err != nil {
		t.Fatalf("deny with the code: %v", err)
	}
	if st := f.status(s); st.Status != pairing.StatusDenied {
		t.Fatalf("status after deny: %q", st.Status)
	}
	exp, err := f.svc.Expect(ctx, a, sensorpairing.ExpectInput{Name: "branch"})
	if err != nil {
		t.Fatal(err)
	}
	eid, _ := shared.IDFromString(exp.ID)
	if err := f.svc.Deny(ctx, b, eid, exp.Code); !errors.Is(err, sensorpairing.ErrNotFound) {
		t.Fatalf("another organization denied the expectation with its code: %v", err)
	}
	if err := f.svc.Deny(ctx, a, eid, ""); err != nil {
		t.Fatalf("deny an expectation: %v", err)
	}
}

func TestPairing_LookupLockIsAudited_DB(t *testing.T) {
	f := newFixture(t)
	f.withTenantsAndAudit()
	ctx := context.Background()
	a := f.org("org-lock")
	f.cleanAudit(a.TenantID)

	for range sensorpairing.LookupFailureLimit + 3 {
		_, _ = f.svc.Lookup(ctx, a, "0000-0000")
	}
	if n := f.auditCount(a.TenantID, "sensor.pairing_lookup_locked"); n != 1 {
		t.Fatalf("lookup lock audited %d times, want once", n)
	}
}

func TestPairing_ReviewClassifiesThePrivateSource_DB(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	a := f.org("org-private")
	s := newSensor(63)
	resp, err := f.svc.Start(ctx, sensorpairing.StartInput{
		Request: pairing.StartRequest{Protocol: pairing.Version, PublicKey: pairing.Encode(s.pub()),
			Commitment: pairing.Encode(s.commitment)},
		PublicKey: s.pub(), SourceIP: net.ParseIP("10.20.30.40"),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.resp = resp
	s.platformPub = f.svc.PlatformPublicKey()
	f.reveal(s)
	v, err := f.svc.Lookup(ctx, a, resp.UserCode)
	if err != nil {
		t.Fatal(err)
	}
	if v.SourceNetwork != "private" || v.SourceProvider != "" {
		t.Fatalf("private source: %q %q", v.SourceNetwork, v.SourceProvider)
	}
}
