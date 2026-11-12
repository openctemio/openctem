package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/crypto"
	"github.com/openctemio/openctem/server/pkg/domain/credential"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

const fpRekeyKeyHex = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"

// insertV1Leak stores a leaked credential the way builds before the
// per-organization fingerprint did: sealed value, install-wide fingerprint,
// no version.
func insertV1Leak(ctx context.Context, t *testing.T, db *sql.DB, p *credential.SecretProtector, tenantID shared.ID, secret string) string {
	t.Helper()
	details := map[string]any{"credential_type": "password", credential.DetailSecretValue: secret}
	if err := p.Seal(tenantID, details, true); err != nil {
		t.Fatal(err)
	}
	details[credential.DetailSecretFingerprint] = p.FingerprintV1(secret)
	delete(details, credential.DetailSecretFingerprintVersion)
	return insertLeakDetails(ctx, t, db, tenantID, details)
}

func insertLeakDetails(ctx context.Context, t *testing.T, db *sql.DB, tenantID shared.ID, details map[string]any) string {
	t.Helper()
	raw, _ := json.Marshal(details)
	var id string
	if err := db.QueryRowContext(ctx, `INSERT INTO exposure_events (tenant_id, event_type, title, fingerprint, source, details)
		VALUES ($1, 'credential_leaked', 'leak', $2, 'test', $3) RETURNING id`, tenantID.String(), shared.NewID().String(), raw).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func leakFingerprint(ctx context.Context, t *testing.T, db *sql.DB, id string) (fp, version string) {
	t.Helper()
	var v sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(details->>'secret_fingerprint', ''), details->>'secret_fingerprint_version'
		FROM exposure_events WHERE id = $1`, id).Scan(&fp, &v); err != nil {
		t.Fatal(err)
	}
	return fp, v.String
}

// The start-up re-key: the same secret leaked for two organizations ends
// with two unrelated fingerprints; inside one organization the same secret
// keeps one fingerprint (dedup); a second run changes nothing; a row whose
// secret cannot be opened is left alone and counted; the reversal gives back
// the old values exactly. A private database: the walk covers every row.
func TestRekeyLeakedCredentialFingerprints_DB(t *testing.T) {
	db := testdb.PrivateDatabase(t, "cred_fp_rekey", "../../../migrations")
	ctx := context.Background()
	c, err := crypto.NewCipherFromHex(fpRekeyKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	p := credential.NewSecretProtector(c, []byte(fpRekeyKeyHex))

	tenantA, tenantB := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	const shared1, other = "Correct-Horse-2026", "another-secret"
	a1 := insertV1Leak(ctx, t, db, p, tenantA, shared1)
	a2 := insertV1Leak(ctx, t, db, p, tenantA, shared1) // same secret, another leak of A
	a3 := insertV1Leak(ctx, t, db, p, tenantA, other)
	b1 := insertV1Leak(ctx, t, db, p, tenantB, shared1)

	// The defect: before the re-key, A and B share a fingerprint.
	if fa, _ := leakFingerprint(ctx, t, db, a1); fa != func() string { f, _ := leakFingerprint(ctx, t, db, b1); return f }() {
		t.Fatal("fixture: v1 fingerprints should match across tenants")
	}

	// A row whose secret no key opens, and an exposure of another kind that
	// carries a fingerprint but no sealed value: neither may be rewritten.
	broken := insertLeakDetails(ctx, t, db, tenantA, map[string]any{
		credential.DetailSecretCiphertext: "bm90LWNpcGhlcnRleHQtYXQtYWxs", credential.DetailSecretScheme: credential.SecretSchemeAESGCM,
		credential.DetailSecretFingerprint: "deadbeef"})
	foreign := insertLeakDetails(ctx, t, db, tenantB, map[string]any{credential.DetailSecretFingerprint: "cafebabe"})

	if n, err := CountLeakedCredentialFingerprintsToRekey(ctx, db); err != nil || n != 5 {
		t.Fatalf("dry-run count = %d (%v), want 5", n, err)
	}

	rep, err := RekeyLeakedCredentialFingerprints(ctx, db, p)
	if err != nil || rep.Rekeyed != 4 || rep.Unrecomputable != 1 {
		t.Fatalf("first run %+v err=%v", rep, err)
	}

	fa1, va1 := leakFingerprint(ctx, t, db, a1)
	fa2, _ := leakFingerprint(ctx, t, db, a2)
	fa3, _ := leakFingerprint(ctx, t, db, a3)
	fb1, vb1 := leakFingerprint(ctx, t, db, b1)
	if va1 != "2" || vb1 != "2" {
		t.Fatalf("versions %q %q", va1, vb1)
	}
	if fa1 == fb1 {
		t.Fatal("cross-tenant: the same secret must have different fingerprints after the re-key")
	}
	if fa1 != p.Fingerprint(tenantA, shared1) || fb1 != p.Fingerprint(tenantB, shared1) {
		t.Fatal("re-keyed fingerprint must be the organization's")
	}
	if fa1 != fa2 || fa1 == fa3 {
		t.Fatalf("per-tenant dedup broken: %s %s %s", fa1, fa2, fa3)
	}
	// A new import of the same secret for A matches the re-keyed rows.
	fresh := map[string]any{credential.DetailSecretValue: shared1}
	if err := p.Seal(tenantA, fresh, false); err != nil || fresh[credential.DetailSecretFingerprint] != fa1 {
		t.Fatalf("new import does not dedup with re-keyed rows: %v", fresh)
	}
	if fp, v := leakFingerprint(ctx, t, db, broken); fp != "deadbeef" || v != "" {
		t.Fatalf("unreadable row rewritten: %s %s", fp, v)
	}
	if fp, v := leakFingerprint(ctx, t, db, foreign); fp != "cafebabe" || v != "" {
		t.Fatalf("row without a sealed value rewritten: %s %s", fp, v)
	}
	// The sealed value is untouched.
	var enc string
	if err := db.QueryRowContext(ctx, `SELECT details->>'secret_value_enc' FROM exposure_events WHERE id = $1`, a1).Scan(&enc); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := p.Open(map[string]any{credential.DetailSecretCiphertext: enc, credential.DetailSecretScheme: credential.SecretSchemeAESGCM}); err != nil || !ok || got != shared1 {
		t.Fatalf("sealed value changed: %q %v %v", got, ok, err)
	}

	// Idempotent.
	rep, err = RekeyLeakedCredentialFingerprints(ctx, db, p)
	if err != nil || rep.Rekeyed != 0 || rep.Unrecomputable != 1 {
		t.Fatalf("second run %+v err=%v", rep, err)
	}
	if again, _ := leakFingerprint(ctx, t, db, a1); again != fa1 {
		t.Fatal("second run changed a fingerprint")
	}

	// Reversible.
	rep, err = RevertLeakedCredentialFingerprints(ctx, db, p)
	if err != nil || rep.Rekeyed != 4 {
		t.Fatalf("revert %+v err=%v", rep, err)
	}
	for _, id := range []string{a1, a2, b1} {
		if fp, v := leakFingerprint(ctx, t, db, id); fp != p.FingerprintV1(shared1) || v != "" {
			t.Fatalf("revert of %s: %s %q", id, fp, v)
		}
	}
	if rep, err = RekeyLeakedCredentialFingerprints(ctx, db, p); err != nil || rep.Rekeyed != 4 {
		t.Fatalf("re-key after revert %+v err=%v", rep, err)
	}
	if fp, _ := leakFingerprint(ctx, t, db, b1); fp != fb1 {
		t.Fatal("re-key after revert must give the same organization fingerprint")
	}
}
