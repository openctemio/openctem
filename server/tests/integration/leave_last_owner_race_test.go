package integration

// Two owners of the same organization leaving at the same moment must not
// leave it without an owner: the last-owner rule is decided on the locked
// owner rows inside the offboarding transaction, not on a read before it.

import (
	"context"
	"errors"
	"sync"
	"testing"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/internal/app/tenant"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/logger"
)

func TestLeaveOrganization_TwoOwnersLeavingTogetherKeepOne(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	pdb := &postgres.DB{DB: db}
	repo := postgres.NewTenantRepository(pdb)
	tsvc := tenant.NewTenantService(repo, logger.NewNop())
	tsvc.SetLifecycleRepository(postgres.NewMemberLifecycleRepository(pdb))

	const rounds = 15
	for round := 0; round < rounds; round++ {
		org := createTestTenant(t, db, "leave-race")
		stamp := shared.NewID().String()[28:]
		a := createTestUser(t, db, "owner-a-"+stamp+"@leaverace.example", "Owner A")
		b := createTestUser(t, db, "owner-b-"+stamp+"@leaverace.example", "Owner B")
		t.Cleanup(func() {
			bg := context.Background()
			_, _ = db.ExecContext(bg, `DELETE FROM audit_logs WHERE tenant_id = $1`, org.String())
			_, _ = db.ExecContext(bg, `DELETE FROM user_roles WHERE tenant_id = $1`, org.String())
			_, _ = db.ExecContext(bg, `DELETE FROM tenant_members WHERE tenant_id = $1`, org.String())
			for _, u := range []shared.ID{a, b} {
				_, _ = db.ExecContext(bg, `DELETE FROM sessions WHERE user_id = $1`, u.String())
				_, _ = db.ExecContext(bg, `DELETE FROM users WHERE id = $1`, u.String())
			}
			cleanupTestData(db, org)
		})
		for _, u := range []shared.ID{a, b} {
			m, err := tenantdom.NewMembership(u, org, tenantdom.RoleOwner, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := repo.CreateMembership(ctx, m); err != nil {
				t.Fatal(err)
			}
		}

		start := make(chan struct{})
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i, u := range []shared.ID{a, b} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[i] = tsvc.LeaveOrganization(ctx, org, u, auditapp.AuditContext{})
			}()
		}
		close(start)
		wg.Wait()

		var left, refused int
		for _, err := range errs {
			switch {
			case err == nil:
				left++
			case errors.Is(err, tenant.ErrSoleOwnerCannotLeave):
				refused++
			default:
				t.Fatalf("round %d: unexpected error %v", round, err)
			}
		}
		var owners int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM tenant_members WHERE tenant_id = $1 AND role = 'owner' AND status = 'active'`, org.String()).Scan(&owners); err != nil {
			t.Fatal(err)
		}
		if owners != 1 || left != 1 || refused != 1 {
			t.Fatalf("round %d: left=%d refused=%d active owners=%d, want exactly one leave and one owner kept", round, left, refused, owners)
		}
	}
}
