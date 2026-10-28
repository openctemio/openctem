package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scope"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Exclusion kinds (research/320): the kind is stored, defaults to
// do_not_scan, only names assets for the closing kinds, and a member whose
// data scope is limited may not make a closing rule that reaches assets
// they cannot see (it would close findings there).

type kindScopeCoverage struct{}

func (kindScopeCoverage) CountCoverage(context.Context, shared.ID, *shared.DataScope) (scopedom.InventoryCoverage, error) {
	return scopedom.InventoryCoverage{}, nil
}

type kindDataScope struct{ ds *shared.DataScope }

func (f kindDataScope) Resolve(context.Context, shared.ID) (*shared.DataScope, error) {
	return f.ds, nil
}

// kindMatches answers all assets for a nil scope and visible ones otherwise.
type kindMatches struct{ all, visible int }

func (m kindMatches) ExclusionMatches(_ context.Context, _ shared.ID, ds *shared.DataScope, items []scope.BulkExclusionItem) ([]scope.ExclusionMatch, error) {
	out := make([]scope.ExclusionMatch, len(items))
	for i := range items {
		if ds == nil {
			out[i].Matched = m.all
		} else {
			out[i].Matched = m.visible
		}
	}
	return out, nil
}

func newKindService(ds *shared.DataScope, m kindMatches) *scope.Service {
	svc, _, _, _ := newTestScopeService()
	svc.SetCoverage(kindScopeCoverage{}, kindDataScope{ds})
	svc.SetExclusionMatches(m)
	return svc
}

func TestExclusionKind(t *testing.T) {
	tenant := shared.NewID()
	restricted := &shared.DataScope{TenantID: tenant}
	unrestricted := &shared.DataScope{TenantID: tenant, Unrestricted: true}
	create := func(svc *scope.Service, typ, pattern, kind string, expires *time.Time) (*scopedom.Exclusion, error) {
		return svc.CreateExclusion(context.Background(), scope.CreateExclusionInput{
			TenantID: tenant.String(), ExclusionType: typ, Pattern: pattern, Reason: "test", CreatedBy: "u1",
			Kind: kind, ExpiresAt: expires,
		})
	}

	t.Run("default is do_not_scan", func(t *testing.T) {
		e, err := create(newKindService(unrestricted, kindMatches{}), "domain", "a.example.com", "", nil)
		if err != nil || e.Kind() != scopedom.ExclusionKindDoNotScan {
			t.Fatalf("kind %v err %v, want do_not_scan", e, err)
		}
		if e.ClosesFindings() {
			t.Fatal("do_not_scan never closes findings")
		}
	})
	t.Run("not_ours is kept and closes when permanent", func(t *testing.T) {
		e, err := create(newKindService(unrestricted, kindMatches{all: 3, visible: 3}), "domain", "*.sold.example.com", "not_ours", nil)
		if err != nil || e.Kind() != scopedom.ExclusionKindNotOurs {
			t.Fatalf("got %v err %v, want a not_ours exclusion", e, err)
		}
		// Without a governance setting the service fails closed to review:
		// a pending exclusion closes nothing until someone approves it.
		if e.ClosesFindings() {
			t.Fatal("a pending exclusion must not close findings")
		}
		if err := e.Approve("approver"); err != nil {
			t.Fatal(err)
		}
		if !e.ClosesFindings() {
			t.Fatal("an approved permanent not_ours exclusion closes findings")
		}
	})
	t.Run("an end date never closes", func(t *testing.T) {
		until := time.Now().Add(72 * time.Hour)
		e, err := create(newKindService(restricted, kindMatches{all: 9, visible: 1}), "domain", "*.maint.example.com", "retired", &until)
		if err != nil {
			t.Fatalf("a temporary exclusion only pauses scanning, whatever the data scope: %v", err)
		}
		if e.ClosesFindings() {
			t.Fatal("a temporary exclusion must not close findings")
		}
	})
	t.Run("unknown kind refused", func(t *testing.T) {
		if _, err := create(newKindService(unrestricted, kindMatches{}), "domain", "b.example.com", "gone", nil); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("err %v, want a validation error", err)
		}
	})
	t.Run("path exclusions cannot say not ours", func(t *testing.T) {
		if _, err := create(newKindService(unrestricted, kindMatches{}), "scanner", "nuclei", "not_ours", nil); !errors.Is(err, scopedom.ErrInvalidExclusionKind) {
			t.Fatalf("err %v, want ErrInvalidExclusionKind", err)
		}
	})
	t.Run("restricted member: closing rule reaching unseen assets refused", func(t *testing.T) {
		_, err := create(newKindService(restricted, kindMatches{all: 5, visible: 2}), "domain", "*.corp.example.com", "not_ours", nil)
		if !errors.Is(err, scope.ErrClosingReachOutsideScope) {
			t.Fatalf("err %v, want ErrClosingReachOutsideScope", err)
		}
	})
	t.Run("restricted member: closing rule within their scope allowed", func(t *testing.T) {
		if _, err := create(newKindService(restricted, kindMatches{all: 2, visible: 2}), "domain", "*.mine.example.com", "not_ours", nil); err != nil {
			t.Fatalf("err %v, want allowed", err)
		}
	})
	t.Run("restricted member: do_not_scan rule reaching unseen assets allowed", func(t *testing.T) {
		if _, err := create(newKindService(restricted, kindMatches{all: 5, visible: 2}), "domain", "*.big.example.com", "do_not_scan", nil); err != nil {
			t.Fatalf("narrowing scanning stays allowed: %v", err)
		}
	})
	t.Run("update to a closing kind is checked too", func(t *testing.T) {
		svc := newKindService(restricted, kindMatches{all: 5, visible: 2})
		e, err := create(svc, "domain", "*.up.example.com", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		k := "retired"
		_, err = svc.UpdateExclusion(context.Background(), e.ID().String(), tenant.String(), scope.UpdateExclusionInput{Kind: &k,
			Reviewer: scopedom.Reviewer{UserID: "u1"}})
		if !errors.Is(err, scope.ErrClosingReachOutsideScope) {
			t.Fatalf("err %v, want ErrClosingReachOutsideScope", err)
		}
	})
}
