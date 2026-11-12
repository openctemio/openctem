package integration

// Credentials never travel in a scan's settings (docs/architecture/task-secrets.md):
// a scanner_config holding one is refused on create (naming the key, never
// the value), and a scan stored with one before the platform refused them
// is blocked at trigger with SCANNER_CONFIG_SECRET: no command carries the
// value. Requires DATABASE_URL.

import (
	"context"
	"errors"
	"strings"
	"testing"

	scansvc "github.com/openctemio/openctem/server/internal/app/scan"
	"github.com/openctemio/openctem/server/pkg/domain/scan"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

const legacySecret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"

func TestScannerConfigSecret_RefusedOnCreateAndNeverCopiedIntoACommand(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	svc := newTriggerService(db)
	tenantID := seedLifecycleTenant(ctx, t, db)
	scanID := seedLifecycleScan(ctx, t, db, tenantID)
	var tool string
	if err := db.QueryRowContext(ctx, `SELECT scanner_name FROM scans WHERE id = $1`, scanID.String()).Scan(&tool); err != nil {
		t.Fatal(err)
	}

	_, err := svc.CreateScan(ctx, scansvc.CreateScanInput{TenantID: tenantID.String(), Name: "secret " + shared.NewID().String(),
		ScanType: "single", ScannerName: tool, ScannerConfig: map[string]any{"github_token": legacySecret},
		Targets: []string{"example.test"}, TenantRunner: true})
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != scan.CodeScannerConfigSecret || !strings.Contains(err.Error(), "github_token") ||
		strings.Contains(err.Error(), legacySecret) {
		t.Fatalf("create with a credential: %v", err)
	}

	// A scan stored with a credential before the platform refused them.
	if _, err := db.ExecContext(ctx, `UPDATE scans SET scanner_config = jsonb_build_object('github_token', $2::text) WHERE id = $1`,
		scanID.String(), legacySecret); err != nil {
		t.Fatal(err)
	}
	_, err = svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{TenantID: tenantID.String(), ScanID: scanID.String()})
	if !errors.As(err, &de) || de.Code != scan.CodeScannerConfigSecret {
		t.Fatalf("trigger of a scan holding a credential: %v", err)
	}
	var carried int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM commands WHERE tenant_id = $1 AND payload::text LIKE '%' || $2 || '%'`,
		tenantID.String(), legacySecret).Scan(&carried); err != nil || carried != 0 {
		t.Fatalf("%d command(s) carry the credential (%v)", carried, err)
	}
	var blocked string
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(error_message, '') FROM scan_runs WHERE tenant_id = $1 AND error_message LIKE '%' || $2 || '%' LIMIT 1`,
		tenantID.String(), legacySecret).Scan(&blocked); err == nil {
		t.Fatal("the blocked run's message repeats the credential")
	}
}
