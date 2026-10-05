package tenant_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	_ "github.com/lib/pq"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Settings writes used to rewrite the whole tenants.settings blob from a
// snapshot read earlier, so a save of one section could silently revert a
// concurrent save of another (an IP allowlist, an MFA requirement, the
// subscribed bundles). These tests pin the per-section compare-and-swap.

type settingsFixture struct {
	raw      *sql.DB
	svc      *tenantapp.TenantService
	tenantID string
}

func newSettingsFixture(t *testing.T) *settingsFixture {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := raw.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	db := &postgres.DB{DB: raw}
	tenantID := shared.NewID().String()
	if _, err := raw.Exec(`INSERT INTO tenants (id, name, slug, settings) VALUES ($1,'Settings Org',$2,'{}'::jsonb)`,
		tenantID, "settings-"+tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = raw.Exec(`DELETE FROM tenants WHERE id=$1`, tenantID) })
	svc := tenantapp.NewTenantService(postgres.NewTenantRepository(db), logger.NewNop())
	return &settingsFixture{raw: raw, svc: svc, tenantID: tenantID}
}

func (f *settingsFixture) section(t *testing.T, key string) map[string]any {
	t.Helper()
	var data []byte
	if err := f.raw.QueryRow(`SELECT COALESCE(settings -> $2::text, 'null'::jsonb) FROM tenants WHERE id=$1`,
		f.tenantID, key).Scan(&data); err != nil {
		t.Fatalf("read section %s: %v", key, err)
	}
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return out
}

func boolPtr(b bool) *bool           { return &b }
func strPtr(s string) *string        { return &s }
func noAudit() auditapp.AuditContext { return auditapp.AuditContext{} }

// Two saves of different sections that race must both persist. With the
// whole-blob write one of them was lost on most runs.
func TestSettingsSections_ConcurrentSavesOfDifferentSectionsBothPersist(t *testing.T) {
	f := newSettingsFixture(t)
	ctx := context.Background()

	for i := 0; i < 25; i++ {
		website := "https://example.com/" + string(rune('a'+i%26))
		mfa := i%2 == 0
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make(chan error, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, err := f.svc.UpdateSecuritySettings(ctx, f.tenantID, tenantapp.UpdateSecuritySettingsInput{
				MFARequired: boolPtr(mfa),
				IPWhitelist: []string{"10.0.0.0/8"},
			}, noAudit())
			errs <- err
		}()
		go func() {
			defer wg.Done()
			<-start
			_, err := f.svc.UpdateGeneralSettings(ctx, f.tenantID, tenantapp.UpdateGeneralSettingsInput{
				Website: strPtr(website),
			}, noAudit())
			errs <- err
		}()
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("iteration %d: save failed: %v", i, err)
			}
		}

		sec := f.section(t, tenantdom.SectionSecurity)
		gen := f.section(t, tenantdom.SectionGeneral)
		if got, _ := sec["mfa_required"].(bool); got != mfa {
			t.Fatalf("iteration %d: security change lost: mfa_required=%v, want %v", i, sec["mfa_required"], mfa)
		}
		if got, _ := gen["website"].(string); got != website {
			t.Fatalf("iteration %d: general change lost: website=%v, want %v", i, gen["website"], website)
		}
	}
}

// A save with a stale If-Match is refused with a conflict and leaves the
// stored section untouched; a save with the current tag goes through.
func TestSettingsSections_StaleIfMatchIsRefused(t *testing.T) {
	f := newSettingsFixture(t)
	ctx := context.Background()

	if _, err := f.svc.UpdateSecuritySettings(ctx, f.tenantID, tenantapp.UpdateSecuritySettingsInput{
		MFARequired: boolPtr(true),
	}, noAudit()); err != nil {
		t.Fatalf("first save: %v", err)
	}
	etags, err := f.svc.SectionETags(ctx, f.tenantID)
	if err != nil {
		t.Fatalf("etags: %v", err)
	}
	readTag := etags[tenantdom.SectionSecurity]

	// Someone else turns MFA off after we read.
	if _, err := f.svc.UpdateSecuritySettings(ctx, f.tenantID, tenantapp.UpdateSecuritySettingsInput{
		MFARequired: boolPtr(false),
	}, noAudit()); err != nil {
		t.Fatalf("concurrent save: %v", err)
	}

	stale := tenantapp.WithSettingsIfMatch(ctx, readTag)
	_, err = f.svc.UpdateSecuritySettings(stale, f.tenantID, tenantapp.UpdateSecuritySettingsInput{
		AllowedDomains: []string{"corp.example"},
	}, noAudit())
	var conflict *tenantdom.SettingsConflictError
	if !errors.As(err, &conflict) || !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale If-Match: err = %v, want *SettingsConflictError", err)
	}
	if conflict.Section != tenantdom.SectionSecurity || conflict.ETag == readTag {
		t.Fatalf("conflict = %+v, want the security section with the current tag", conflict)
	}
	if doms, _ := f.section(t, tenantdom.SectionSecurity)["allowed_domains"].([]any); len(doms) != 0 {
		t.Fatalf("stale save was applied: allowed_domains = %v", doms)
	}

	fresh := tenantapp.WithSettingsIfMatch(ctx, conflict.ETag)
	if _, err := f.svc.UpdateSecuritySettings(fresh, f.tenantID, tenantapp.UpdateSecuritySettingsInput{
		AllowedDomains: []string{"corp.example"},
	}, noAudit()); err != nil {
		t.Fatalf("save with current tag: %v", err)
	}
	sec := f.section(t, tenantdom.SectionSecurity)
	if doms, _ := sec["allowed_domains"].([]any); len(doms) != 1 {
		t.Fatalf("allowed_domains = %v, want [corp.example]", sec["allowed_domains"])
	}
	if mfa, _ := sec["mfa_required"].(bool); mfa {
		t.Fatalf("mfa_required = true; the concurrent change to false was reverted")
	}
}

// Keys a section writer does not own survive every section save: the bundle
// subscription (written by its own jsonb_set) and the lifecycle dry-run stamp.
func TestSettingsSections_OtherKeysSurviveASectionSave(t *testing.T) {
	f := newSettingsFixture(t)
	ctx := context.Background()

	if _, err := f.raw.Exec(`UPDATE tenants SET settings = settings || '{"subscribed_bundles":["asm"]}'::jsonb WHERE id=$1`,
		f.tenantID); err != nil {
		t.Fatalf("seed bundles: %v", err)
	}
	if _, err := f.svc.UpdateSecuritySettings(ctx, f.tenantID, tenantapp.UpdateSecuritySettingsInput{
		IPWhitelist: []string{"192.0.2.0/24"},
	}, noAudit()); err != nil {
		t.Fatalf("security save: %v", err)
	}
	if err := f.svc.StampAssetLifecycleDryRunCompleted(ctx, f.tenantID); err != nil {
		t.Fatalf("stamp: %v", err)
	}
	if _, err := f.svc.UpdateTenant(ctx, f.tenantID, tenantapp.UpdateTenantInput{Name: strPtr("Renamed Org")}); err != nil {
		t.Fatalf("profile save: %v", err)
	}

	var bundles []byte
	if err := f.raw.QueryRow(`SELECT settings -> 'subscribed_bundles' FROM tenants WHERE id=$1`, f.tenantID).Scan(&bundles); err != nil {
		t.Fatalf("read bundles: %v", err)
	}
	if string(bundles) != `["asm"]` {
		t.Fatalf("subscribed_bundles = %s, want [\"asm\"]", bundles)
	}
	if ips, _ := f.section(t, tenantdom.SectionSecurity)["ip_whitelist"].([]any); len(ips) != 1 {
		t.Fatalf("ip_whitelist lost after the stamp/profile save: %v", ips)
	}
	if f.section(t, tenantdom.SectionAssetLifecycle)["dry_run_completed_at"] == nil {
		t.Fatalf("dry-run stamp not written")
	}
}

// A stored security section that cannot be decoded is never replaced by the
// permissive defaults: the save is refused, reads fail closed, and saves of
// other sections leave it alone.
func TestSettingsSections_CorruptSectionFailsClosed(t *testing.T) {
	f := newSettingsFixture(t)
	ctx := context.Background()

	corrupt := `{"mfa_required":"yes","ip_whitelist":["10.0.0.0/8"]}`
	if _, err := f.raw.Exec(`UPDATE tenants SET settings = jsonb_build_object('security', $2::jsonb) WHERE id=$1`,
		f.tenantID, corrupt); err != nil {
		t.Fatalf("seed corrupt section: %v", err)
	}

	_, err := f.svc.UpdateSecuritySettings(ctx, f.tenantID, tenantapp.UpdateSecuritySettingsInput{
		AllowedDomains: []string{"corp.example"},
	}, noAudit())
	if !errors.Is(err, tenantdom.ErrSettingsSectionCorrupt) {
		t.Fatalf("save over a corrupt section: err = %v, want ErrSettingsSectionCorrupt", err)
	}

	if _, err := f.svc.UpdateGeneralSettings(ctx, f.tenantID, tenantapp.UpdateGeneralSettingsInput{
		Website: strPtr("https://example.com"),
	}, noAudit()); err != nil {
		t.Fatalf("general save next to a corrupt security section: %v", err)
	}
	var sec []byte
	if err := f.raw.QueryRow(`SELECT settings -> 'security' FROM tenants WHERE id=$1`, f.tenantID).Scan(&sec); err != nil {
		t.Fatalf("read security: %v", err)
	}
	var got, want any
	_ = json.Unmarshal(sec, &got)
	_ = json.Unmarshal([]byte(corrupt), &want)
	if gb, _ := json.Marshal(got); string(gb) != mustJSON(want) {
		t.Fatalf("corrupt security section was rewritten: %s", sec)
	}

	tn, err := f.svc.GetTenant(ctx, f.tenantID)
	if err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	if _, err := tn.SecuritySettingsStrict(); !errors.Is(err, tenantdom.ErrSettingsSectionCorrupt) {
		t.Fatalf("SecuritySettingsStrict on a corrupt section: err = %v, want ErrSettingsSectionCorrupt", err)
	}
	// The other sections still decode (the old whole-blob decode reset all).
	if tn.TypedSettings().General.Website != "https://example.com" {
		t.Fatalf("general section not decoded next to a corrupt one: %+v", tn.TypedSettings().General)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
