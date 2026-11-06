package deploymentregion

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	cst "github.com/openctemio/openctem/api/internal/app/consolesetting/consolesettingtest"
)

type orgs struct{ exist bool }

func (o orgs) AnyOrganization(context.Context) (bool, error) { return o.exist, nil }

func newSvc(t *testing.T, env string, tenants bool) (*Service, *cst.Audit, *cst.Notifier) {
	t.Helper()
	repo, audit, n := cst.NewRepo(), &cst.Audit{}, &cst.Notifier{}
	repo.Tenants = tenants
	return NewService(repo, orgs{exist: tenants}, cst.Recorder(audit, n), env, nil), audit, n
}

// The region is set once, before the first organization, and is immutable
// afterwards; the change is critical and told to every administrator.
func TestSetOnceThenImmutable(t *testing.T) {
	svc, audit, n := newSvc(t, "", false)
	ctx := context.Background()
	got, err := svc.Get(ctx)
	if err != nil || !got.Settable || got.Region != "" || got.Source != SourceNone {
		t.Fatalf("before: %+v %v", got, err)
	}
	got, err = svc.Set(ctx, cst.SuperAdmin(t), "eu-central", "data residency for EU customers", "203.0.113.5", "test")
	if err != nil || got.Region != "eu-central" || got.Settable || got.Source != SourceConsole {
		t.Fatalf("after: %+v %v", got, err)
	}
	if svc.Region(ctx) != "eu-central" {
		t.Fatal("new organizations must get the console region")
	}
	if _, err := svc.Set(ctx, cst.SuperAdmin(t), "us-east", "change it", "", ""); !errors.Is(err, ErrAlreadySet) {
		t.Fatalf("a second set must be refused: %v", err)
	}
	if svc.Region(ctx) != "eu-central" {
		t.Fatal("the region must not move")
	}
	if len(audit.Entries) != 1 || audit.Entries[0].Action != ActionSet || n.Count() != 1 {
		t.Fatalf("audit %d, notices %d", len(audit.Entries), n.Count())
	}
}

// Once an organization exists the region can no longer be set: it would
// differ from the organizations already created.
func TestRefusedWhenOrganizationsExist(t *testing.T) {
	svc, audit, _ := newSvc(t, "", true)
	ctx := context.Background()
	if got, _ := svc.Get(ctx); got.Settable {
		t.Fatal("not settable once organizations exist")
	}
	if _, err := svc.Set(ctx, cst.SuperAdmin(t), "eu-central", "late", "", ""); !errors.Is(err, ErrOrganizationsExist) {
		t.Fatalf("err = %v", err)
	}
	if len(audit.Entries) != 0 || svc.Region(ctx) != "" {
		t.Fatal("a refused set changes nothing")
	}
}

// DEPLOYMENT_REGION pins the region.
func TestEnvironmentLocks(t *testing.T) {
	svc, _, _ := newSvc(t, "ap-south", false)
	ctx := context.Background()
	if _, err := svc.Set(ctx, cst.SuperAdmin(t), "eu-central", "x", "", ""); !errors.Is(err, ErrLockedByEnvironment) {
		t.Fatalf("err = %v", err)
	}
	got, _ := svc.Get(ctx)
	if !got.LockedByEnvironment || got.Region != "ap-south" || got.Settable || svc.Region(ctx) != "ap-south" {
		t.Fatalf("got %+v", got)
	}
}

// The shape and the reason are checked.
func TestValidation(t *testing.T) {
	svc, _, _ := newSvc(t, "", false)
	ctx := context.Background()
	if _, err := svc.Set(ctx, cst.SuperAdmin(t), "EU Central!", "x", "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed: %v", err)
	}
	if _, err := svc.Set(ctx, cst.SuperAdmin(t), "eu-central", " ", "", ""); !errors.Is(err, consolesetting.ErrReasonRequired) {
		t.Fatalf("no reason: %v", err)
	}
	if _, err := svc.Set(ctx, nil, "eu-central", "x", "", ""); !errors.Is(err, ErrNoActor) {
		t.Fatalf("no actor: %v", err)
	}
}
