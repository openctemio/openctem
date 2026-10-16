package signup

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	signupdom "github.com/openctemio/openctem/api/pkg/domain/signup"
)

type memRepo struct {
	mu     sync.Mutex
	st     *signupdom.State
	getErr error
}

func (m *memRepo) Get(context.Context) (signupdom.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getErr != nil {
		return signupdom.State{}, m.getErr
	}
	if m.st == nil {
		return signupdom.State{}, signupdom.ErrNotFound
	}
	return *m.st, nil
}

func (m *memRepo) CreateIfAbsent(_ context.Context, s signupdom.State) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st != nil {
		return false, nil
	}
	s.Version = 1
	m.st = &s
	return true, nil
}

func (m *memRepo) Update(_ context.Context, p signupdom.Policy, expected int, by shared.ID, at time.Time) (signupdom.State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st == nil || m.st.Version != expected {
		return signupdom.State{}, signupdom.ErrVersionConflict
	}
	m.st = &signupdom.State{Policy: p, Version: expected + 1, Source: signupdom.SourceConsole, UpdatedBy: &by, UpdatedAt: at}
	return *m.st, nil
}

type memAudit struct {
	admin.AuditLogRepository
	rows []*admin.AuditLog
}

func (m *memAudit) Create(_ context.Context, l *admin.AuditLog) error {
	m.rows = append(m.rows, l)
	return nil
}

type staticAdmins []*admin.AdminUser

func (s staticAdmins) ListActive(context.Context) ([]*admin.AdminUser, error) { return s, nil }

type recNotifier struct{ alerts []ChangeAlert }

func (r *recNotifier) NotifySignupPolicyChanged(_ context.Context, a ChangeAlert) error {
	r.alerts = append(r.alerts, a)
	return nil
}

func mustAdmin(t *testing.T, email string) *admin.AdminUser {
	t.Helper()
	a, err := admin.NewAdminUser(email, "A", admin.AdminRoleSuperAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// openService is a service under the open ceiling (SIGNUP_MODE=open).
func openService(repo signupdom.Repository, audit admin.AuditLogRepository, admins AdminLister, n ChangeNotifier) *Service {
	svc := NewService(repo, audit, admins, n, nil)
	svc.SetCeiling(signupdom.CeilingOpen)
	return svc
}

func TestSeed_EnvironmentSeedsOnceAndStoredValueWins(t *testing.T) {
	repo := &memRepo{}
	svc := openService(repo, nil, nil, nil)
	ctx := context.Background()
	if err := svc.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	if got := svc.Current(ctx); got.Mode != signupdom.ModeSelfService {
		t.Fatalf("seed must store the environment value, got %s", got.Mode)
	}
	st, _ := repo.Get(ctx)
	if st.Source != signupdom.SourceEnvironment {
		t.Fatalf("seeded source = %s", st.Source)
	}
	// A later start with another env value does not override the stored one.
	if err := NewService(repo, nil, nil, nil, nil).Seed(ctx); err != nil {
		t.Fatal(err)
	}
	if st2, _ := repo.Get(ctx); st2.Policy.Mode != signupdom.ModeSelfService {
		t.Fatal("the stored policy must win over the environment")
	}
}

func TestSeed_ClosedCeilingsSeedAdminOnly(t *testing.T) {
	for _, c := range []signupdom.Ceiling{"", signupdom.CeilingDisabled, signupdom.CeilingDomain} {
		repo := &memRepo{}
		svc := NewService(repo, nil, nil, nil, nil)
		svc.SetCeiling(c)
		if err := svc.Seed(context.Background()); err != nil {
			t.Fatal(err)
		}
		if st, _ := repo.Get(context.Background()); st.Policy.Mode != signupdom.ModeAdminOnly {
			t.Fatalf("ceiling %q must seed admin_only, got %s", c, st.Policy.Mode)
		}
	}
}

// The console cannot open more than SIGNUP_MODE: a write above the ceiling is
// refused before anything is stored, audited or sent, and a stored
// self_service policy is clamped on read when the ceiling is lowered later.
func TestCeiling_LocksConsole(t *testing.T) {
	ctx := context.Background()
	actor := mustAdmin(t, "alice@op.example")
	for _, c := range []signupdom.Ceiling{"", signupdom.CeilingDisabled, signupdom.CeilingDomain} {
		repo := &memRepo{}
		audit := &memAudit{}
		n := &recNotifier{}
		svc := NewService(repo, audit, staticAdmins{actor, mustAdmin(t, "bob@op.example")}, n, nil)
		svc.SetCeiling(c)
		_ = svc.Seed(ctx)
		if _, err := svc.Update(ctx, actor, signupdom.Policy{Mode: signupdom.ModeSelfService}, 1, "", ""); !errors.Is(err, signupdom.ErrLockedByDeployment) {
			t.Fatalf("ceiling %q: expected ErrLockedByDeployment, got %v", c, err)
		}
		if st, _ := repo.Get(ctx); st.Version != 1 || st.Policy.AllowsSelfService() || len(audit.rows) != 0 || len(n.alerts) != 0 {
			t.Fatalf("ceiling %q: a refused change writes nothing (%+v, %d audit, %d alerts)", c, st, len(audit.rows), len(n.alerts))
		}
		// Request access stays a console choice under every ceiling.
		if _, err := svc.Update(ctx, actor, signupdom.Policy{Mode: signupdom.ModeAdminOnly, RequestAccess: true}, 1, "", ""); err != nil {
			t.Fatalf("ceiling %q: request access must be allowed: %v", c, err)
		}
	}

	// Stored self_service (from an earlier open deployment) is clamped once
	// the ceiling is lowered, with no console change.
	repo := &memRepo{}
	_ = openService(repo, nil, nil, nil).Seed(ctx)
	lowered := NewService(repo, nil, nil, nil, nil)
	lowered.SetCeiling(signupdom.CeilingDisabled)
	if lowered.Current(ctx).AllowsSelfService() {
		t.Fatal("a lowered ceiling must close self-service at once")
	}
	if st, _ := lowered.Get(ctx); !st.Policy.AllowsSelfService() {
		t.Fatal("Get reports the stored policy; only the policy in force is clamped")
	}
}

// Without working e-mail, public sign-up is closed: every self-registered
// address must be verified.
func TestEffective_NoMailClosesPublicSignup(t *testing.T) {
	ctx := context.Background()
	svc := openService(&memRepo{}, nil, nil, nil)
	_ = svc.Seed(ctx)
	ready := false
	svc.SetMailReady(func() bool { return ready })
	if svc.Current(ctx).AllowsSelfService() {
		t.Fatal("no e-mail: self-service must be closed")
	}
	ready = true
	if !svc.Current(ctx).AllowsSelfService() {
		t.Fatal("with e-mail the stored self_service policy is in force")
	}
}

func TestCurrent_FailsClosed(t *testing.T) {
	repo := &memRepo{getErr: errors.New("db down")}
	svc := NewService(repo, nil, nil, nil, nil)
	if got := svc.Current(context.Background()); got.Mode != signupdom.ModeAdminOnly || got.RequestAccess {
		t.Fatalf("a read error must mean admin_only, got %+v", got)
	}
	// Nothing stored: admin_only too.
	if got := NewService(&memRepo{}, nil, nil, nil, nil).Current(context.Background()); got.Mode != signupdom.ModeAdminOnly {
		t.Fatalf("nothing stored must mean admin_only, got %+v", got)
	}
}

func TestUpdate_AuditsCriticalAndNotifiesOtherAdmins(t *testing.T) {
	repo := &memRepo{}
	audit := &memAudit{}
	actor := mustAdmin(t, "alice@op.example")
	other := mustAdmin(t, "bob@op.example")
	notifier := &recNotifier{}
	svc := NewService(repo, audit, staticAdmins{actor, other}, notifier, nil)
	ctx := context.Background()
	_ = svc.Seed(ctx)
	svc.SetCeiling(signupdom.CeilingOpen)
	// Warm the cache with the old value: the update must replace it.
	if svc.Current(ctx).AllowsSelfService() {
		t.Fatal("seeded admin_only")
	}

	st, err := svc.Update(ctx, actor, signupdom.Policy{Mode: signupdom.ModeSelfService, RequestAccess: true}, 1, "203.0.113.7", "ua")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if st.Version != 2 || st.Source != signupdom.SourceConsole {
		t.Fatalf("unexpected state %+v", st)
	}
	if !svc.Current(ctx).AllowsSelfService() {
		t.Fatal("the change must take effect on this replica at once")
	}
	if len(audit.rows) != 1 || audit.rows[0].Severity != admin.SeverityCritical || audit.rows[0].Action != ActionPolicyChanged {
		t.Fatalf("expected one critical audit row, got %+v", audit.rows)
	}
	if len(notifier.alerts) != 1 {
		t.Fatalf("expected one notification, got %d", len(notifier.alerts))
	}
	got := notifier.alerts[0]
	if len(got.Recipients) != 1 || got.Recipients[0] != "bob@op.example" {
		t.Fatalf("only the other administrators are told, got %v", got.Recipients)
	}
	if got.Previous.Mode != signupdom.ModeAdminOnly || got.Current.Mode != signupdom.ModeSelfService {
		t.Fatalf("alert must carry before and after, got %+v", got)
	}
}

func TestUpdate_Refusals(t *testing.T) {
	actor := mustAdmin(t, "alice@op.example")
	ctx := context.Background()

	t.Run("stale version", func(t *testing.T) {
		repo := &memRepo{}
		audit := &memAudit{}
		svc := openService(repo, audit, nil, nil)
		_ = svc.Seed(ctx)
		repo.st.Policy = signupdom.Default()
		if _, err := svc.Update(ctx, actor, signupdom.Policy{Mode: signupdom.ModeSelfService}, 7, "", ""); !errors.Is(err, signupdom.ErrVersionConflict) {
			t.Fatalf("expected a version conflict, got %v", err)
		}
		if len(audit.rows) != 0 || svc.Current(ctx).AllowsSelfService() {
			t.Fatal("a refused change writes nothing")
		}
	})
	t.Run("invalid mode", func(t *testing.T) {
		svc := NewService(&memRepo{}, nil, nil, nil, nil)
		if _, err := svc.Update(ctx, actor, signupdom.Policy{Mode: "everyone"}, 0, "", ""); !errors.Is(err, signupdom.ErrInvalidPolicy) {
			t.Fatalf("expected invalid policy, got %v", err)
		}
	})
	t.Run("no administrator", func(t *testing.T) {
		svc := NewService(&memRepo{}, nil, nil, nil, nil)
		if _, err := svc.Update(ctx, nil, signupdom.Policy{Mode: signupdom.ModeSelfService}, 0, "", ""); !errors.Is(err, ErrNoActor) {
			t.Fatalf("expected ErrNoActor, got %v", err)
		}
	})
}

// With nothing stored (no seed ran), the first save works from version 0.
func TestUpdate_NothingStoredStartsFromVersionZero(t *testing.T) {
	svc := openService(&memRepo{}, nil, nil, nil)
	st, err := svc.Update(context.Background(), mustAdmin(t, "a@op.example"), signupdom.Policy{Mode: signupdom.ModeSelfService}, 0, "", "")
	if err != nil || !st.Policy.AllowsSelfService() {
		t.Fatalf("expected the first save to work, got %+v %v", st, err)
	}
}
