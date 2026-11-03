package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// Per-use-case AI settings on the real table: one key per use case written
// without touching the others or another organization; the downgrade writes
// only over the value it read; the sweep lists only organizations that turned
// AI on; the override count reads only AI-filed requests of the organization
// decided since auto-apply was turned on. Requires DATABASE_URL.
func TestTenantAIUseCases_DB(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	repo := NewTenantAISettingsRepository(&DB{DB: sqlDB})

	a, b := shared.NewID(), shared.NewID()
	for _, id := range []shared.ID{a, b} {
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'use cases', $2)`, id.String(), "uc-"+id.String()); err != nil {
			t.Fatal(err)
		}
		id := id
		t.Cleanup(func() {
			_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String())
		})
	}

	// No row: nothing stored, defaults apply.
	pol, err := repo.GetUseCases(ctx, a)
	if err != nil || len(pol) != 0 || pol.For(aidom.UseCaseTriage) != aidom.DefaultUseCaseSetting() {
		t.Fatalf("no row: %+v %v", pol, err)
	}

	since := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	auto := aidom.DefaultUseCaseSetting()
	auto.Mode, auto.MinConfidence, auto.AutoApplySince = aidom.UseCaseAutoApply, 0.9, &since
	if err := repo.SaveUseCase(ctx, a, aidom.UseCaseTriage, auto); err != nil {
		t.Fatal(err)
	}
	off := aidom.DefaultUseCaseSetting()
	off.Mode, off.Ceiling = aidom.UseCaseOff, aidom.DataClassPublic
	if err := repo.SaveUseCase(ctx, a, aidom.UseCaseSummary, off); err != nil {
		t.Fatal(err)
	}
	pol, err = repo.GetUseCases(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if got := pol.For(aidom.UseCaseTriage); got.Mode != aidom.UseCaseAutoApply || got.MinConfidence != 0.9 || got.AutoApplySince == nil || !got.AutoApplySince.Equal(since) {
		t.Fatalf("triage after a second key was saved: %+v", got)
	}
	if got := pol.For(aidom.UseCaseSummary); got.Mode != aidom.UseCaseOff || got.Ceiling != aidom.DataClassPublic {
		t.Fatalf("summary: %+v", got)
	}
	// The row carries no consent.
	if s, err := repo.Get(ctx, a, tenant.AISettings{}); err != nil || s.OptedIn() {
		t.Fatalf("saving a use case turned AI on: %+v %v", s, err)
	}
	// Another organization is untouched.
	if pb, err := repo.GetUseCases(ctx, b); err != nil || len(pb) != 0 {
		t.Fatalf("another organization: %+v %v", pb, err)
	}

	// The sweep sees only organizations that turned AI on.
	listed := func() bool {
		list, err := repo.ListAutoApply(ctx, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range list {
			if x.TenantID == a && x.UseCase == aidom.UseCaseTriage {
				return true
			}
		}
		return false
	}
	if listed() {
		t.Fatal("an organization with AI off is in the sweep")
	}
	if _, err := sqlDB.ExecContext(ctx, `UPDATE tenant_ai_settings SET enabled_at = now(), enabled_by = 'admin' WHERE tenant_id = $1`, a.String()); err != nil {
		t.Fatal(err)
	}
	if !listed() {
		t.Fatal("an organization in auto-apply is missing from the sweep")
	}

	// Override count: AI-filed requests of this organization decided since.
	finding := func(tid shared.ID) string {
		id := uuid.NewString()
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO findings (id, tenant_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1::uuid, $2, 'sast', 'uc', 'm', 'medium', $1::text, 'new')`, id, tid.String()); err != nil {
			t.Fatal(err)
		}
		return id
	}
	decided := func(tid shared.ID, status string, created time.Time, aiActor bool) {
		actor := any(nil)
		if aiActor {
			actor = "ai_triage"
		}
		col := "approved_at"
		if status == "rejected" {
			col = "rejected_at"
		}
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO finding_status_approvals (tenant_id, finding_id, requested_status, justification, status, created_at, requested_by_actor, `+col+`)
			VALUES ($1, $2, 'false_positive', 'j', $3, $4, $5, $4)`, tid.String(), finding(tid), status, created, actor); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	decided(a, "rejected", now, true)
	decided(a, "approved", now, true)
	decided(a, "approved", now, true)
	decided(a, "rejected", since.Add(-time.Hour), true) // before auto-apply was turned on
	decided(a, "rejected", now, false)                  // a person's own request
	decided(b, "rejected", now, true)                   // another organization
	st, err := repo.OverrideStats(ctx, a, aidom.UseCaseTriage, since, 50)
	if err != nil {
		t.Fatal(err)
	}
	if st.Decisions != 3 || st.Overrides != 1 {
		t.Fatalf("override stats: %+v, want 3 decisions with 1 override", st)
	}
	if st, _ := repo.OverrideStats(ctx, a, aidom.UseCaseTriage, since, 1); st.Decisions != 1 {
		t.Fatalf("window: %+v", st)
	}
	if st, _ := repo.OverrideStats(ctx, a, aidom.UseCaseSummary, since, 50); st.Decisions != 0 {
		t.Fatalf("summary files no requests: %+v", st)
	}

	// Downgrade writes only over the value it read.
	stored := pol.For(aidom.UseCaseTriage)
	next := stored
	next.Mode, next.AutoApplySince = aidom.UseCaseSuggest, nil
	at := time.Now().UTC().Truncate(time.Microsecond)
	next.DowngradedAt, next.DowngradeReason = &at, aidom.DowngradeReasonOverrides
	stale := stored
	stale.MinConfidence = 0.5
	if ok, err := repo.DowngradeUseCase(ctx, a, aidom.UseCaseTriage, stale, next); err != nil || ok {
		t.Fatalf("downgrade over a stale read: %v %v", ok, err)
	}
	if ok, err := repo.DowngradeUseCase(ctx, b, aidom.UseCaseTriage, stored, next); err != nil || ok {
		t.Fatalf("downgrade in another organization: %v %v", ok, err)
	}
	if ok, err := repo.DowngradeUseCase(ctx, a, aidom.UseCaseTriage, stored, next); err != nil || !ok {
		t.Fatalf("downgrade: %v %v", ok, err)
	}
	if ok, _ := repo.DowngradeUseCase(ctx, a, aidom.UseCaseTriage, stored, next); ok {
		t.Fatal("a second downgrade over the same read")
	}
	pol, _ = repo.GetUseCases(ctx, a)
	if got := pol.For(aidom.UseCaseTriage); got.Mode != aidom.UseCaseSuggest || got.DowngradedAt == nil || got.DowngradeReason != aidom.DowngradeReasonOverrides {
		t.Fatalf("after downgrade: %+v", got)
	}
	if got := pol.For(aidom.UseCaseSummary); got.Mode != aidom.UseCaseOff {
		t.Fatalf("downgrade touched another use case: %+v", got)
	}
}
