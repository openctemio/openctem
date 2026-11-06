package postgres

import (
	"context"
	"testing"
	"time"
)

// Legacy secret fingerprints (written before the keyed fingerprint) are
// cleared in batches; newer ones, other tenants' and every other field stay.
func TestClearLegacySecretFingerprints_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)
	otherAsset := seedOwnedAsset(ctx, t, db, other, nil)
	cutoff := time.Now().Add(-time.Hour)

	seed := func(tn, _ any, created time.Time, fp string) string {
		tid, aid := tenant, asset
		if tn == other {
			tid, aid = other, otherAsset
		}
		fid := seedOpenFinding(ctx, t, db, tid, openFindingSeed{asset: aid, source: "secret", tool: "betterleaks", rule: "r"})
		id := fid.String()
		if _, err := db.ExecContext(ctx, `UPDATE findings SET created_at = $2,
			type_details = jsonb_build_object('v', 1, 'secret', jsonb_build_object('fingerprint', $3::text, 'masked_value', 'ab…yz'))
			WHERE id = $1`, id, created, fp); err != nil {
			t.Fatal(err)
		}
		return id
	}
	old := []string{
		seed(tenant, asset, cutoff.Add(-time.Hour), "legacy1"),
		seed(tenant, asset, cutoff.Add(-time.Hour), "legacy2"),
		seed(tenant, asset, cutoff.Add(-time.Hour), "legacy3"),
	}
	fresh := seed(tenant, asset, cutoff.Add(time.Minute), "keyed")
	foreign := seed(other, otherAsset, cutoff.Add(-time.Hour), "legacy-other")

	fp := func(id string) string {
		var v string
		if err := db.QueryRowContext(ctx, `SELECT COALESCE(type_details->'secret'->>'fingerprint', '') FROM findings WHERE id = $1`, id).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}

	// Dry run counts and changes nothing.
	rep, err := ClearLegacySecretFingerprints(ctx, db, &tenant, cutoff, false, 2)
	if err != nil || rep.Matched != 3 || rep.Applied {
		t.Fatalf("dry run = %+v, %v", rep, err)
	}
	if fp(old[0]) == "" {
		t.Fatal("a dry run cleared a fingerprint")
	}

	// Applied in batches of 2: all three go, across two statements.
	rep, err = ClearLegacySecretFingerprints(ctx, db, &tenant, cutoff, true, 2)
	if err != nil || rep.Matched != 3 || rep.Remaining != 0 {
		t.Fatalf("apply = %+v, %v", rep, err)
	}
	for _, id := range old {
		if fp(id) != "" {
			t.Errorf("legacy fingerprint of %s kept", id)
		}
	}
	if fp(fresh) != "keyed" {
		t.Error("a fingerprint written after the cutoff was cleared")
	}
	if fp(foreign) != "legacy-other" {
		t.Error("another tenant's fingerprint was cleared by a tenant-scoped run")
	}
	// The rest of the secret document stays.
	var masked string
	if err := db.QueryRowContext(ctx, `SELECT type_details->'secret'->>'masked_value' FROM findings WHERE id = $1`, old[0]).Scan(&masked); err != nil || masked != "ab…yz" {
		t.Fatalf("masked value = %q, %v", masked, err)
	}
	// Idempotent.
	rep, err = ClearLegacySecretFingerprints(ctx, db, &tenant, cutoff, true, 2)
	if err != nil || rep.Matched != 0 {
		t.Fatalf("rerun = %+v, %v", rep, err)
	}
}
