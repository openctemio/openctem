package unit

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"

	"github.com/stretchr/testify/require"
)

// enableLifecycleBody is what a client sends to turn the lifecycle on: the
// settings only, no dry_run_completed_at (the server records its own dry run).
const enableLifecycleBody = `{"enabled": true, "grace_period_days": 14, "pause_on_integration_failure": true,
	"stale_threshold_days": 30, "manual_reactivation_grace_days": 7}`

func putAssetLifecycle(t *testing.T, repo *mockTenantRepo, tenantID shared.ID, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := newTenantHandlerForScoring(repo)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/api/v1/tenants/test-org/settings/asset-lifecycle", bytes.NewBufferString(body))
	req = withTeamContext(req, tenantID)
	rec := httptest.NewRecorder()
	h.UpdateAssetLifecycleSettings(rec, req)
	return rec
}

// After a successful dry run (stamped server-side for the tenant), enabling
// the lifecycle succeeds without the client echoing dry_run_completed_at, and
// the stored stamp is kept.
func TestAssetLifecycleHandler_EnableAfterServerDryRun(t *testing.T) {
	repo := newMockTenantRepo()
	tn, tenantID := createTenantWithSettings(repo)
	settings := tn.TypedSettings()
	stamp := int64(1_800_000_000)
	settings.AssetLifecycle.DryRunCompletedAt = &stamp
	require.NoError(t, tn.UpdateSettings(settings))

	rec := putAssetLifecycle(t, repo, tenantID, enableLifecycleBody)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	got := repo.tenants[tenantID.String()].TypedSettings().AssetLifecycle
	require.True(t, got.Enabled)
	require.NotNil(t, got.DryRunCompletedAt)
	require.Equal(t, stamp, *got.DryRunCompletedAt)
}

// Without a dry run of its own, the tenant cannot enable the lifecycle, and a
// timestamp the client makes up does not count.
func TestAssetLifecycleHandler_EnableWithoutDryRunRefused(t *testing.T) {
	for name, body := range map[string]string{
		"no stamp":     enableLifecycleBody,
		"forged stamp": `{"enabled": true, "grace_period_days": 14, "dry_run_completed_at": 1800000000}`,
	} {
		t.Run(name, func(t *testing.T) {
			repo := newMockTenantRepo()
			_, tenantID := createTenantWithSettings(repo)

			rec := putAssetLifecycle(t, repo, tenantID, body)
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			require.Contains(t, rec.Body.String(), "dry-run")

			got := repo.tenants[tenantID.String()].TypedSettings().AssetLifecycle
			require.False(t, got.Enabled)
			require.Nil(t, got.DryRunCompletedAt)
		})
	}
}

// Another tenant's dry run never unlocks this tenant.
func TestAssetLifecycleHandler_OtherTenantsDryRunDoesNotCount(t *testing.T) {
	repo := newMockTenantRepo()
	other, _ := createTenantWithSettings(repo)
	settings := other.TypedSettings()
	stamp := int64(1_800_000_000)
	settings.AssetLifecycle.DryRunCompletedAt = &stamp
	require.NoError(t, other.UpdateSettings(settings))

	mine, err := tenant.NewTenant("Mine", "mine-org", "user-2")
	require.NoError(t, err)
	require.NoError(t, mine.UpdateSettings(tenant.DefaultSettings()))
	repo.tenants[mine.ID().String()] = mine

	rec := putAssetLifecycle(t, repo, mine.ID(), enableLifecycleBody)
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.False(t, repo.tenants[mine.ID().String()].TypedSettings().AssetLifecycle.Enabled)
}
