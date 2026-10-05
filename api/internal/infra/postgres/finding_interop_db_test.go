package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Source interoperability data (migration 001078): written by fingerprint
// within the caller's tenant only, read back by (tenant, id) only, the latest
// sighting replaces what it carries, and the column CHECKs refuse oversized
// rows written by any other path.
func TestFindingInterop_DB(t *testing.T) {
	f := newCoverageFixture(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: f.db})

	insert := func(tenant, asset shared.ID, fp, status, source string) shared.ID {
		id := shared.NewID()
		f.exec(t, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1, $2, $3, $4, 'nessus', 'm', 'high', $5, $6)`, id, tenant, asset, source, fp, status)
		return id
	}
	mine := insert(f.tenant, f.host, "fp-shared", "open", "va")

	otherTenant := shared.NewID()
	f.exec(t, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, otherTenant, "interop-o-"+otherTenant.String())
	t.Cleanup(func() { _, _ = f.db.ExecContext(ctx, "DELETE FROM tenants WHERE id = $1", otherTenant.String()) })
	otherAsset := shared.NewID()
	f.exec(t, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'h-o', 'host')`, otherAsset, otherTenant)
	// The other tenant has a finding under the very same fingerprint.
	foreign := insert(otherTenant, otherAsset, "fp-shared", "open", "va")

	v81, v92 := 8.1, 9.2
	cred := true
	asOf := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	data := vulnerability.InteropData{
		Native: &vulnerability.InteropNative{Scheme: "nessus", VulnID: "201194", Severity: "3", Status: "reopened", Credentialed: &cred},
		Scores: []vulnerability.InteropScore{
			{System: "cvss", Version: "3.1", Value: &v81, Source: "nvd"},
			{System: "cvss", Version: "4.0", Value: &v92, Source: "vendor"},
		},
		VulnerabilityIDs: []vulnerability.InteropVulnID{{Type: "cve", ID: "CVE-2024-6387"}},
		Lifecycle:        &vulnerability.InteropLifecycle{TimesFound: 41, State: "reopened"},
		Solution:         &vulnerability.InteropSolution{Type: "upgrade"},
		VEX:              &vulnerability.InteropVEX{Status: "not_affected", Justification: "component_not_present", Source: "vex-doc-1", AsOf: &asOf},
		SourceExtra:      map[string]string{"plugin_type": "remote"},
		LocationKey:      "net:22/tcp",
	}
	n, err := repo.UpdateInteropBatch(ctx, f.tenant, []vulnerability.InteropUpdate{{Fingerprint: "fp-shared", Data: data}})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if n != 1 {
		t.Fatalf("updated %d rows, want 1 (only the caller's tenant)", n)
	}

	got, err := repo.GetInterop(ctx, f.tenant, mine)
	if err != nil || got == nil {
		t.Fatalf("get: %v %v", got, err)
	}
	if got.Native == nil || got.Native.VulnID != "201194" || got.Native.Credentialed == nil || !*got.Native.Credentialed {
		t.Errorf("native = %+v", got.Native)
	}
	if len(got.Scores) != 2 || *got.Scores[1].Value != 9.2 || got.Scores[1].Version != "4.0" {
		t.Errorf("scores = %+v", got.Scores)
	}
	if got.VEX == nil || got.VEX.Justification != "component_not_present" || got.VEX.AsOf == nil || !got.VEX.AsOf.Equal(asOf) {
		t.Errorf("vex = %+v", got.VEX)
	}
	if got.LocationKey != "net:22/tcp" || got.SourceExtra["plugin_type"] != "remote" || got.Lifecycle.TimesFound != 41 {
		t.Errorf("data = %+v", got)
	}
	var nativeID string
	if err := f.db.QueryRowContext(ctx, `SELECT native_vuln_id FROM findings WHERE id = $1`, mine.String()).Scan(&nativeID); err != nil || nativeID != "201194" {
		t.Errorf("native_vuln_id = %q %v", nativeID, err)
	}

	// Cross-tenant: the other tenant's row under the same fingerprint was not
	// written, and reading this tenant's finding as the other tenant fails.
	if d, err := repo.GetInterop(ctx, otherTenant, foreign); err != nil || d != nil {
		t.Errorf("foreign finding got interop data: %+v %v", d, err)
	}
	if _, err := repo.GetInterop(ctx, otherTenant, mine); err == nil {
		t.Error("read another tenant's finding")
	}

	// A later sighting replaces what it carries and keeps the rest; a new
	// VEX statement replaces the old one as a whole.
	_, err = repo.UpdateInteropBatch(ctx, f.tenant, []vulnerability.InteropUpdate{{Fingerprint: "fp-shared", Data: vulnerability.InteropData{
		VEX: &vulnerability.InteropVEX{Status: "affected"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	got, _ = repo.GetInterop(ctx, f.tenant, mine)
	if got.VEX.Status != "affected" || got.VEX.Justification != "" || got.VEX.Source != "" {
		t.Errorf("vex not replaced as a whole: %+v", got.VEX)
	}
	if got.Native == nil || len(got.Scores) != 2 {
		t.Errorf("members the sighting did not carry were lost: %+v", got)
	}

	// Hostile values are bounded before storage.
	huge := strings.Repeat("x", 10000)
	_, err = repo.UpdateInteropBatch(ctx, f.tenant, []vulnerability.InteropUpdate{{Fingerprint: "fp-shared", Data: vulnerability.InteropData{
		Native:      &vulnerability.InteropNative{VulnID: huge},
		SourceExtra: map[string]string{"k\x00": "v", "ok": huge},
	}}})
	if err != nil {
		t.Fatalf("bounded update: %v", err)
	}
	got, _ = repo.GetInterop(ctx, f.tenant, mine)
	if len(got.Native.VulnID) != vulnerability.MaxInteropIDText || len(got.SourceExtra["ok"]) != vulnerability.MaxInteropSourceExtraValue {
		t.Errorf("not bounded: vuln id %d, extra %d", len(got.Native.VulnID), len(got.SourceExtra["ok"]))
	}
	if _, bad := got.SourceExtra["k\x00"]; bad {
		t.Error("key with a control character stored")
	}

	// The CHECK constraint is the backstop for any other writer.
	if _, err := f.db.ExecContext(ctx, `UPDATE findings SET vex_status = 'maybe' WHERE id = $1`, mine.String()); err == nil {
		t.Error("CHECK accepted an unknown vex_status")
	}
	if _, err := f.db.ExecContext(ctx, `UPDATE findings SET scores = '{"a":1}'::jsonb WHERE id = $1`, mine.String()); err == nil {
		t.Error("CHECK accepted non-array scores")
	}
}

// VEX not_affected: only open, non-human findings of the caller's tenant, on
// the stated asset and key, become false_positive with the reason; dry run
// changes nothing.
func TestApplyVEXNotAffected_DB(t *testing.T) {
	f := newCoverageFixture(t)
	ctx := context.Background()
	repo := NewFindingRepository(&DB{DB: f.db})

	insert := func(tenant, asset shared.ID, status, source string) (shared.ID, string) {
		id := shared.NewID()
		fp := "vex-" + id.String()
		f.exec(t, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1, $2, $3, $4, 'trivy', 'm', 'high', $5, $6)`, id, tenant, asset, source, fp, status)
		return id, fp
	}
	open, openFP := insert(f.tenant, f.host, "new", "sca")
	accepted, accFP := insert(f.tenant, f.host, "accepted", "sca")
	resolved, resFP := insert(f.tenant, f.host, "resolved", "sca")
	pentest, penFP := insert(f.tenant, f.host, "confirmed", "pentest")

	otherTenant := shared.NewID()
	f.exec(t, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, otherTenant, "vex-o-"+otherTenant.String())
	t.Cleanup(func() { _, _ = f.db.ExecContext(ctx, "DELETE FROM tenants WHERE id = $1", otherTenant.String()) })
	otherAsset := shared.NewID()
	f.exec(t, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'h-o', 'host')`, otherAsset, otherTenant)
	foreign, foreignFP := insert(otherTenant, otherAsset, "new", "sca")

	reason := vulnerability.VEXResolutionText(&vulnerability.InteropVEX{Status: "not_affected", Justification: "component_not_present", Source: "vex-doc"})
	items := []vulnerability.VEXNotAffected{
		{Fingerprint: openFP, AssetID: f.host.String(), Resolution: reason},
		{Fingerprint: accFP, AssetID: f.host.String(), Resolution: reason},
		{Fingerprint: resFP, AssetID: f.host.String(), Resolution: reason},
		{Fingerprint: penFP, AssetID: f.host.String(), Resolution: reason},
		// Right key, wrong asset.
		{Fingerprint: openFP, AssetID: f.otherHost.String(), Resolution: reason},
		// Another tenant's finding, named with its own key and asset.
		{Fingerprint: foreignFP, AssetID: otherAsset.String(), Resolution: reason},
	}

	ids, err := repo.ApplyVEXNotAffected(ctx, f.tenant, items, true)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if len(ids) != 1 || ids[0] != open {
		t.Fatalf("dry run matched %v, want only %s", ids, open)
	}
	if got := f.status(t, open); got != "new" {
		t.Fatalf("dry run changed the status to %q", got)
	}

	ids, err = repo.ApplyVEXNotAffected(ctx, f.tenant, items, false)
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if len(ids) != 1 || ids[0] != open {
		t.Fatalf("enforce closed %v, want only %s", ids, open)
	}
	var status, resolution, method string
	if err := f.db.QueryRowContext(ctx, `SELECT status, resolution, resolution_method FROM findings WHERE id = $1`, open.String()).
		Scan(&status, &resolution, &method); err != nil {
		t.Fatal(err)
	}
	if status != "false_positive" || method != "vex_not_affected" || !strings.Contains(resolution, "component_not_present") || !strings.Contains(resolution, "vex-doc") {
		t.Errorf("closed finding: %s / %s / %s", status, method, resolution)
	}
	for id, want := range map[shared.ID]string{accepted: "accepted", resolved: "resolved", pentest: "confirmed", foreign: "new"} {
		if got := f.status(t, id); got != want {
			t.Errorf("finding %s is %q, want %q (must not be touched)", id, got, want)
		}
	}
	// Idempotent: a second run closes nothing more.
	if ids, _ := repo.ApplyVEXNotAffected(ctx, f.tenant, items, false); len(ids) != 0 {
		t.Errorf("second run closed %v", ids)
	}
}
