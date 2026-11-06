package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The reset clears mask-derived fingerprints and RE…ED previews of secret
// findings of one tenant only; a dry run changes nothing; later fingerprints,
// other finding types and other tenants stay; the grouped rotation tasks are
// counted; a rerun is a no-op.
func TestResetMaskSecretFingerprints_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)
	otherAsset := seedOwnedAsset(ctx, t, db, other, nil)
	cutoff := time.Now().Add(-time.Hour)
	old := cutoff.Add(-time.Hour)

	seed := func(tid, aid shared.ID, findingType string, created time.Time, fp, preview string) string {
		id := seedOpenFinding(ctx, t, db, tid, openFindingSeed{asset: aid, source: "secret", tool: "betterleaks", rule: "r"}).String()
		if _, err := db.ExecContext(ctx, `UPDATE findings SET created_at = $2, finding_type = $5,
			type_details = jsonb_build_object('v', 1, 'secret', jsonb_build_object('fingerprint', $3::text, 'masked_preview', $4::text, 'scopes', jsonb_build_array('repo')))
			WHERE id = $1`, id, created, fp, preview, findingType); err != nil {
			t.Fatal(err)
		}
		return id
	}
	s1 := seed(tenant, asset, "secret", old, "maskfp", "RE…ED")
	s2 := seed(tenant, asset, "secret", old, "maskfp", "RE…ED")
	s3 := seed(tenant, asset, "secret", old, "maskfp", "AKIA…MPLE")
	fresh := seed(tenant, asset, "secret", cutoff.Add(time.Minute), "rawfp", "")
	freshRE := seed(tenant, asset, "secret", cutoff.Add(time.Minute), "rawfp", "RE…ED")
	notSecret := seed(tenant, asset, "vulnerability", old, "maskfp", "RE…ED")
	foreign := seed(other, otherAsset, "secret", old, "maskfp", "RE…ED")

	// s1 and s2 share one rotation task (the over-grouping); s3 has its own.
	var actionID, taskID string
	if err := db.QueryRowContext(ctx, `INSERT INTO remediation_actions (tenant_id, action_key, kind, title, origin)
		VALUES ($1, 'rotate:secret:maskfp', 'rotate', 'Rotate', 'manual') RETURNING id`, tenant.String()).Scan(&actionID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO remediation_tasks (tenant_id, action_id, title)
		VALUES ($1, $2, 'Rotate') RETURNING id`, tenant.String(), actionID).Scan(&taskID); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{s1, s2} {
		if _, err := db.ExecContext(ctx, `INSERT INTO remediation_task_members (tenant_id, task_id, finding_id, join_source)
			VALUES ($1, $2, $3, 'manual')`, tenant.String(), taskID, f); err != nil {
			t.Fatal(err)
		}
	}

	field := func(id, key string) string {
		var v string
		if err := db.QueryRowContext(ctx, `SELECT COALESCE(type_details->'secret'->>$2, '') FROM findings WHERE id = $1`, id, key).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}

	// Dry run: counts only, nothing changes.
	rep, err := ResetMaskSecretFingerprints(ctx, db, tenant, cutoff, false, 2)
	if err != nil || rep.Applied || rep.Fingerprints != 3 || rep.Previews != 3 || rep.GroupedRotationTasks != 1 || len(rep.FindingIDs) != 0 {
		t.Fatalf("dry run = %+v, %v", rep, err)
	}
	if field(s1, "fingerprint") == "" || field(s1, "masked_preview") == "" {
		t.Fatal("a dry run changed a finding")
	}

	rep, err = ResetMaskSecretFingerprints(ctx, db, tenant, cutoff, true, 2)
	if err != nil || rep.Fingerprints != 3 || rep.Previews != 3 || rep.Remaining != 0 || len(rep.FindingIDs) != 4 {
		t.Fatalf("apply = %+v, %v", rep, err)
	}
	for _, id := range []string{s1, s2, s3} {
		if field(id, "fingerprint") != "" {
			t.Errorf("mask fingerprint of %s kept", id)
		}
	}
	if field(s1, "masked_preview") != "" || field(s2, "masked_preview") != "" || field(freshRE, "masked_preview") != "" {
		t.Error("a RE…ED preview was kept")
	}
	if field(s3, "masked_preview") != "AKIA…MPLE" {
		t.Error("a real preview was cleared")
	}
	if field(s1, "scopes") == "" {
		t.Error("the rest of the secret document was dropped")
	}
	if field(fresh, "fingerprint") != "rawfp" || field(freshRE, "fingerprint") != "rawfp" {
		t.Error("a fingerprint written after the cutoff was cleared")
	}
	if field(notSecret, "fingerprint") != "maskfp" || field(notSecret, "masked_preview") != "RE…ED" {
		t.Error("a finding that is not a secret was changed")
	}
	if field(foreign, "fingerprint") != "maskfp" || field(foreign, "masked_preview") != "RE…ED" {
		t.Error("another tenant's finding was changed")
	}
	rep, err = ResetMaskSecretFingerprints(ctx, db, tenant, cutoff, true, 2)
	if err != nil || rep.Fingerprints != 0 || rep.Previews != 0 || rep.GroupedRotationTasks != 0 {
		t.Fatalf("rerun = %+v, %v", rep, err)
	}

	tenants, err := MaskSecretResetTenants(ctx, db, &other, cutoff)
	if err != nil || len(tenants) != 1 || tenants[0] != other {
		t.Fatalf("tenants = %v, %v", tenants, err)
	}
}
