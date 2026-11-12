package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// criticalMatches answers every item with matched assets and critical-tier
// open findings, and counts the whole-organization lookups.
type criticalMatches struct {
	critical int
	calls    *int
}

func (m criticalMatches) ExclusionMatches(_ context.Context, _ shared.ID, _ *shared.DataScope, items []scope.BulkExclusionItem) ([]scope.ExclusionMatch, error) {
	if m.calls != nil {
		*m.calls++
	}
	out := make([]scope.ExclusionMatch, len(items))
	for i := range items {
		out[i] = scope.ExclusionMatch{Matched: 1, OpenFindings: m.critical + 1, CriticalFindings: m.critical}
	}
	return out, nil
}

// Marking an asset out of scope for good (not ours or retired, no end date)
// closes its findings; when that would close critical, P0 or KEV findings
// the caller must confirm (research/438): the request is refused with
// EXCLUSION_CLOSES_CRITICAL_FINDINGS (a conflict) and nothing is written.
// Do not scan and temporary exclusions close nothing and need no confirm.
func TestExclusionCriticalClosuresNeedConfirm(t *testing.T) {
	ctx := context.Background()
	tenant := shared.NewID()
	full := &shared.DataScope{TenantID: tenant, Unrestricted: true}
	svcWith := func(critical int) (*scope.Service, *mockExclusionRepo) {
		svc, _, er, _ := newTestScopeService()
		svc.SetCoverage(kindScopeCoverage{}, kindDataScope{full})
		svc.SetExclusionMatches(criticalMatches{critical: critical})
		return svc, er
	}
	create := func(svc *scope.Service, kind string, expires *time.Time, confirm bool) error {
		_, err := svc.CreateExclusion(ctx, scope.CreateExclusionInput{
			TenantID: tenant.String(), ExclusionType: "domain", Pattern: "gone.example.com", Reason: "sold",
			CreatedBy: "u1", Kind: kind, ExpiresAt: expires, ConfirmCritical: confirm,
		})
		return err
	}
	wantRefused := func(t *testing.T, err error) {
		t.Helper()
		var de *shared.DomainError
		if !errors.Is(err, scope.ErrClosesCriticalFindings) || !errors.As(err, &de) ||
			de.Code != scope.CodeClosesCriticalFindings || !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("err %v, want %s (conflict)", err, scope.CodeClosesCriticalFindings)
		}
	}

	t.Run("not ours with critical findings is refused without confirm", func(t *testing.T) {
		svc, er := svcWith(2)
		wantRefused(t, create(svc, "not_ours", nil, false))
		if len(er.exclusions) != 0 {
			t.Fatalf("a refused request wrote %d exclusions", len(er.exclusions))
		}
	})
	t.Run("retired with confirm is created", func(t *testing.T) {
		svc, _ := svcWith(2)
		if err := create(svc, "retired", nil, true); err != nil {
			t.Fatalf("confirmed: %v", err)
		}
	})
	t.Run("no critical findings needs no confirm", func(t *testing.T) {
		svc, _ := svcWith(0)
		if err := create(svc, "not_ours", nil, false); err != nil {
			t.Fatalf("no critical: %v", err)
		}
	})
	t.Run("do not scan and temporary close nothing", func(t *testing.T) {
		svc, _ := svcWith(5)
		if err := create(svc, "do_not_scan", nil, false); err != nil {
			t.Fatalf("do_not_scan: %v", err)
		}
		end := time.Now().Add(72 * time.Hour)
		svc2, _ := svcWith(5)
		if err := create(svc2, "not_ours", &end, false); err != nil {
			t.Fatalf("temporary: %v", err)
		}
	})
	t.Run("bulk is refused as a whole before writing", func(t *testing.T) {
		svc, er := svcWith(1)
		items := []scope.BulkExclusionItem{
			{ExclusionType: "domain", Pattern: "a.gone.example.com"},
			{ExclusionType: "domain", Pattern: "b.gone.example.com"},
		}
		_, err := svc.CreateExclusions(ctx, scope.BulkExclusionsInput{
			TenantID: tenant.String(), Items: items, CreatedBy: "u1", Kind: "not_ours",
		})
		wantRefused(t, err)
		if len(er.exclusions) != 0 {
			t.Fatalf("a refused bulk request wrote %d exclusions", len(er.exclusions))
		}
		out, err := svc.CreateExclusions(ctx, scope.BulkExclusionsInput{
			TenantID: tenant.String(), Items: items, CreatedBy: "u1", Kind: "not_ours", ConfirmCritical: true,
		})
		if err != nil || len(out) != 2 || out[0].Err != nil || out[1].Err != nil {
			t.Fatalf("confirmed bulk: %v %+v", err, out)
		}
	})
	t.Run("changing do not scan to not ours needs the confirm", func(t *testing.T) {
		svc, _ := svcWith(0)
		if err := create(svc, "do_not_scan", nil, false); err != nil {
			t.Fatal(err)
		}
		list, err := svc.ListExclusions(ctx, scope.ListExclusionsInput{TenantID: tenant.String()})
		if err != nil || len(list.Data) != 1 {
			t.Fatalf("list: %v %d", err, len(list.Data))
		}
		svc.SetExclusionMatches(criticalMatches{critical: 3})
		kind := "not_ours"
		_, err = svc.UpdateExclusion(ctx, list.Data[0].ID().String(), tenant.String(), scope.UpdateExclusionInput{Kind: &kind})
		wantRefused(t, err)
		if _, err := svc.UpdateExclusion(ctx, list.Data[0].ID().String(), tenant.String(),
			scope.UpdateExclusionInput{Kind: &kind, ConfirmCritical: true}); err != nil {
			t.Fatalf("confirmed kind change: %v", err)
		}
	})
}
