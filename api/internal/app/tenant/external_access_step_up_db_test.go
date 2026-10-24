package tenant_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Changing when an external member's access ends needs a recent sign-in when
// it widens access (a later end, or re-enabling a member whose access ended);
// shortening it does not. A refused change stores nothing.
func TestExtendMemberAccess_WideningNeedsStepUp(t *testing.T) {
	e := newFirstOwnerEnv(t)
	org := e.org()
	adminID, memberUser, membershipID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, u := range []string{adminID, memberUser} {
		if _, err := e.db.Exec(`INSERT INTO users (id, email) VALUES ($1, $2)`, u, "ext-"+u[:8]+"@it.test"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.db.Exec(`INSERT INTO tenant_members (id, user_id, tenant_id, role, status, joined_at) VALUES ($1, $2, $3, 'admin', 'active', now())`,
		uuid.NewString(), adminID, org); err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Add(10 * 24 * time.Hour).Truncate(time.Second)
	if _, err := e.db.Exec(`INSERT INTO tenant_members (id, user_id, tenant_id, role, status, joined_at, kind, home_domain, expires_at)
		VALUES ($1, $2, $3, 'member', 'active', now(), 'external', 'partner.example', $4)`, membershipID, memberUser, org, start); err != nil {
		t.Fatal(err)
	}

	audit := auditapp.NewAuditService(postgres.NewAuditRepository(e.pg), e.log)
	svc := func(gate shared.RecentAuthGate) *tenantapp.TenantService {
		s := tenantapp.NewTenantService(postgres.NewTenantRepository(e.pg), e.log, tenantapp.WithTenantAuditService(audit))
		s.SetStepUpGate(gate)
		return s
	}
	actx := auditapp.AuditContext{TenantID: org, ActorID: adminID, ActorEmail: "admin@it.test"}
	stale := driftStepUp{err: shared.ErrForbidden}
	end := func(d time.Duration) tenantapp.ExtendMemberAccessInput {
		at := time.Now().UTC().Add(d).Truncate(time.Second)
		return tenantapp.ExtendMemberAccessInput{ExpiresAt: &at, Reason: "contract"}
	}
	stored := func() time.Time {
		var at time.Time
		if err := e.db.QueryRow(`SELECT expires_at FROM tenant_members WHERE id = $1`, membershipID).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}

	// Later end without a recent sign-in: refused, nothing stored.
	if _, err := svc(stale).ExtendMemberAccess(context.Background(), membershipID, end(60*24*time.Hour), actx); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("widening without step-up: err = %v, want forbidden", err)
	}
	if !stored().Equal(start) {
		t.Fatal("a refused widening changed the end of access")
	}
	// Shorter end: no step-up needed.
	if _, err := svc(stale).ExtendMemberAccess(context.Background(), membershipID, end(2*24*time.Hour), actx); err != nil {
		t.Fatalf("shortening without step-up: %v", err)
	}
	// Later end with a recent sign-in: allowed.
	if _, err := svc(driftStepUp{}).ExtendMemberAccess(context.Background(), membershipID, end(60*24*time.Hour), actx); err != nil {
		t.Fatalf("widening with step-up: %v", err)
	}

	// Re-enabling a member whose access ended also needs the sign-in.
	if _, err := e.db.Exec(`UPDATE tenant_members SET status = 'suspended', suspended_reason = 'expired', expires_at = now() - interval '1 day' WHERE id = $1`, membershipID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc(stale).ExtendMemberAccess(context.Background(), membershipID, end(5*24*time.Hour), actx); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("re-enable without step-up: err = %v, want forbidden", err)
	}
	var status string
	_ = e.db.QueryRow(`SELECT status FROM tenant_members WHERE id = $1`, membershipID).Scan(&status)
	if status != "suspended" {
		t.Fatalf("a refused re-enable left status %q", status)
	}
	if _, err := svc(driftStepUp{}).ExtendMemberAccess(context.Background(), membershipID, end(5*24*time.Hour), actx); err != nil {
		t.Fatalf("re-enable with step-up: %v", err)
	}
}
