package integration

// An asset merge re-keys version-2 findings by rewriting the asset field of
// their stored identity tuple (RFC-043 §4.1.6), inside the merge transaction:
// a collision folds the two into the earliest-created finding, never a
// delete; a tuple that no longer reproduces its stored key is left alone; and
// nothing outside the merging tenant is touched.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func scaKey(t *testing.T, asset shared.ID, purl, cve string) vulnerability.IdentityKey {
	t.Helper()
	k, ok := vulnerability.SCAIdentity(asset.String(), purl, "", "", cve, cve)
	if !ok {
		t.Fatalf("no SCA identity for %s %s", purl, cve)
	}
	return k
}

// v2 inserts a finding keyed by a version-2 identity, as ingest stores it.
func (f *mergeFixture) v2(asset shared.ID, k vulnerability.IdentityKey, status string, created time.Time) shared.ID {
	f.t.Helper()
	raw, err := vulnerability.MarshalIdentityKey(k)
	if err != nil {
		f.t.Fatal(err)
	}
	id := shared.NewID()
	if _, err := f.db.Exec(`
		INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, status,
			fingerprint, fingerprint_version, identity_key, created_at, updated_at)
		VALUES ($1,$2,$3,'sca','trivy','finding','high',$4,$5,2,$6::jsonb,$7,$7)`,
		id.String(), f.tenant.String(), asset.String(), status, k.Fingerprint(), string(raw), created); err != nil {
		f.t.Fatalf("insert v2 finding: %v", err)
	}
	return id
}

func (f *mergeFixture) identityOf(id shared.ID) vulnerability.IdentityKey {
	f.t.Helper()
	var raw []byte
	if err := f.db.QueryRow(`SELECT identity_key FROM findings WHERE id = $1`, id.String()).Scan(&raw); err != nil {
		f.t.Fatalf("read identity key: %v", err)
	}
	k, err := vulnerability.ParseIdentityKey(raw)
	if err != nil {
		f.t.Fatalf("stored identity key %s: %v", raw, err)
	}
	return k
}

func TestAssetMerge_VersionTwoIdentityFollowsTheKeptAsset(t *testing.T) {
	f := newMergeFixture(t, "merge-v2")
	const purl, cve = "pkg:npm/lodash@4.17.15", "CVE-2021-23337"

	// The same vulnerability on both assets: the merged asset's copy is older
	// and triaged, the kept asset's copy is newer.
	triaged := f.v2(f.away, scaKey(t, f.away, purl, cve), "accepted", time.Now().Add(-72*time.Hour))
	if _, err := f.db.Exec(`UPDATE findings SET work_item_uris = ARRAY['JIRA-7'] WHERE id = $1`, triaged.String()); err != nil {
		t.Fatal(err)
	}
	newer := f.v2(f.keep, scaKey(t, f.keep, purl, cve), "new", time.Now().Add(-time.Hour))
	// A finding only the merged asset has.
	unique := f.v2(f.away, scaKey(t, f.away, purl, "CVE-2020-8203"), "new", time.Now())
	// A stored tuple that no longer reproduces its key (edited by hand, or a
	// recipe bug): rewriting it could fold it into an unrelated finding.
	drifted := f.v2(f.away, scaKey(t, f.away, purl, "CVE-2019-10744"), "new", time.Now())
	driftedFP := shared.NewID().String() + "-drifted"
	if _, err := f.db.Exec(`UPDATE findings SET fingerprint = $2 WHERE id = $1`, drifted.String(), driftedFP); err != nil {
		t.Fatal(err)
	}
	awayKey := f.state(triaged).fingerprint
	before := f.count(`SELECT count(*) FROM findings WHERE tenant_id = $1`, f.tenant.String())

	// Another tenant holds a finding under the key the merged copy will get.
	other := newMergeFixture(t, "merge-v2-other")
	foreign := other.v2(other.keep, scaKey(t, f.keep, purl, "CVE-2020-8203"), "accepted", time.Now().Add(-96*time.Hour))

	f.merge()

	if n := f.count(`SELECT count(*) FROM findings WHERE tenant_id = $1`, f.tenant.String()); n != before {
		t.Fatalf("%d findings after the merge, %d before: a row was deleted", n, before)
	}
	want := scaKey(t, f.keep, purl, cve)
	s := f.state(triaged)
	if s.asset != f.keep.String() || s.fingerprint != want.Fingerprint() || s.status != "accepted" || len(s.tickets) != 1 {
		t.Fatalf("older triaged finding did not survive on the kept asset with its state: %+v", s)
	}
	if got := f.identityOf(triaged); got.Field(vulnerability.IdentityFieldAsset) != f.keep.String() || got.Fingerprint() != s.fingerprint {
		t.Fatalf("stored tuple not rewritten for the kept asset: %+v", got)
	}
	if l := f.state(newer); l.status != "duplicate" || !l.duplicateOf.Valid || l.duplicateOf.String != triaged.String() {
		t.Fatalf("newer copy is not a tombstone of the survivor: %+v", l)
	}
	if got := aliasOwner(t, f.db, f.tenant, awayKey); got != triaged.String() {
		t.Fatalf("the merged asset's key belongs to %q, want the survivor", got)
	}

	u := f.state(unique)
	if wantU := scaKey(t, f.keep, purl, "CVE-2020-8203"); u.fingerprint != wantU.Fingerprint() || u.status != "new" {
		t.Fatalf("unique finding not re-keyed for the kept asset: %+v", u)
	}
	raw, _ := json.Marshal(f.identityOf(unique))
	if f.identityOf(unique).Field(vulnerability.IdentityFieldAsset) != f.keep.String() {
		t.Fatalf("unique finding's tuple still names the merged asset: %s", raw)
	}

	if d := f.state(drifted); d.fingerprint != driftedFP || d.status != "new" {
		t.Fatalf("a drifted tuple was rewritten: %+v", d)
	}

	// Tenant isolation: the other tenant's finding under the same key is a
	// different finding and stays as it was.
	if fs := other.state(foreign); fs.status != "accepted" || fs.duplicateOf.Valid {
		t.Fatalf("another tenant's finding changed: %+v", fs)
	}
	if u.duplicateOf.Valid {
		t.Fatalf("the merged finding was folded into another tenant's: %+v", u)
	}
}
