package rekey

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/credential"
	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/domain/secretstore"
)

func randomHexKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// freshDB creates a private database migrated to head, so the run (which
// touches every row of the registered tables, and sweeps the whole schema)
// never sees rows other packages' DB tests write concurrently. Skipped
// unless DATABASE_URL is set and the role may create databases.
func freshDB(t *testing.T) *sql.DB {
	t.Helper()
	return testdb.PrivateDatabase(t, "rekey", filepath.Join("..", "..", "..", "migrations"))
}

// seedAll writes a value under key into every registered location and
// returns the plaintexts by location name.
func seedAll(t *testing.T, db *sql.DB, key string) map[string]string {
	t.Helper()
	c, err := crypto.NewCipherFromKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	enc := func(p string) string {
		v, err := c.EncryptString(p)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("seed %q: %v", q[:min(len(q), 60)], err)
		}
	}
	plain := map[string]string{}
	put := func(loc, p string) string { plain[loc] = p; return enc(p) }

	tenantID := "11111111-1111-7111-8111-111111111111"
	userID := "22222222-2222-7222-8222-222222222222"
	adminID := "33333333-3333-7333-8333-333333333333"
	intgID := "44444444-4444-7444-8444-444444444444"

	exec(`INSERT INTO tenants (id, name, slug, settings) VALUES ($1, 'rekey', 'rekey', jsonb_build_object('ai', jsonb_build_object('api_key', $2::text)))`,
		tenantID, "enc:v1:"+put("tenants.settings.ai.api_key", "sk-llm-key"))
	exec(`INSERT INTO users (id, email) VALUES ($1, 'rekey@example.com')`, userID)
	exec(`INSERT INTO admin_users (id, email, name) VALUES ($1, 'admin@example.com', 'Admin')`, adminID)

	exec(`INSERT INTO integrations (id, tenant_id, name, category, provider, credentials_encrypted, metadata)
		VALUES ($1, $2, 'jira', 'ticketing', 'jira', $3, jsonb_build_object('webhook_secret_encrypted', $4::text))`,
		intgID, tenantID, put("integrations.credentials_encrypted", `{"token":"jira"}`),
		put("integrations.metadata.webhook_secret_encrypted", "jira-hook-secret"))
	exec(`INSERT INTO integration_scm_extensions (integration_id, webhook_secret_encrypted) VALUES ($1, convert_to($2, 'UTF8'))`,
		intgID, put("integration_scm_extensions.webhook_secret_encrypted", "scm-hook-secret"))
	exec(`INSERT INTO tenant_identity_providers (tenant_id, provider, display_name, client_id, client_secret_encrypted)
		VALUES ($1, 'okta', 'Okta', 'cid', $2)`, tenantID, put("tenant_identity_providers.client_secret_encrypted", "org-sso-secret"))
	exec(`INSERT INTO platform_identity_provider (display_name, issuer, client_id, client_secret_encrypted, redirect_uri,
		authorization_endpoint, token_endpoint, jwks_uri) VALUES ('IdP', 'https://idp', 'cid', $1, 'https://r', 'https://a', 'https://t', 'https://j')`,
		put("platform_identity_provider.client_secret_encrypted", "platform-idp-secret"))
	exec(`INSERT INTO admin_idp_login_states (state_hash, nonce, code_verifier_encrypted, expires_at) VALUES ('sh', 'n', $1, NOW() + interval '5 minutes')`,
		put("admin_idp_login_states.code_verifier_encrypted", "pkce-verifier"))
	exec(`INSERT INTO admin_credentials (admin_id, mfa_secret_encrypted) VALUES ($1, $2)`,
		adminID, put("admin_credentials.mfa_secret_encrypted", "ADMINTOTPSECRET"))
	exec(`INSERT INTO user_mfa (user_id, secret_encrypted, pending_secret_encrypted) VALUES ($1, $2, $3)`,
		userID, put("user_mfa.secret_encrypted", "USERTOTPSECRET"), put("user_mfa.pending_secret_encrypted", "PENDINGTOTP"))
	exec(`INSERT INTO settings (tenant_id, key, value_json) VALUES ($1, 'storage_config',
		jsonb_build_object('provider', 's3', 'access_key', $2::text, 'secret_key', $3::text))`,
		tenantID, put("settings.value_json.access_key", "AKIASTORAGE"), put("settings.value_json.secret_key", "storage-secret"))

	// Leaked credential, sealed by the production protector.
	details := map[string]any{credential.DetailSecretValue: "hunter2-leaked", "credential_type": "password"}
	if err := credential.NewSecretProtector(c, []byte(key)).Seal(details); err != nil {
		t.Fatal(err)
	}
	plain["exposure_events.details.secret_value_enc"] = "hunter2-leaked"
	raw, _ := json.Marshal(details)
	exec(`INSERT INTO exposure_events (tenant_id, event_type, title, fingerprint, source, details)
		VALUES ($1, 'credential_leaked', 'leak', 'fp-rekey', 'test', $2)`, tenantID, raw)

	// Secret store row, sealed by the production secret-store encryptor.
	store, err := secretstore.NewEncryptor(secretstore.KeyFromConfig(key))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := store.Encrypt([]byte(`{"password":"git-pass"}`))
	if err != nil {
		t.Fatal(err)
	}
	plain["credentials.encrypted_data"] = `{"password":"git-pass"}`
	exec(`INSERT INTO credentials (tenant_id, name, credential_type, encrypted_data) VALUES ($1, 'git', 'basic_auth', $2)`, tenantID, sealed)

	content := []byte("id: rekey-template\n")
	plain["scanner_templates.signature_hash"] = string(content)
	exec(`INSERT INTO scanner_templates (tenant_id, name, template_type, content, content_hash, signature_hash)
		VALUES ($1, 'tmpl', 'nuclei', $2, $3, $4)`, tenantID, content, scannertemplate.ComputeHash(content),
		scannertemplate.ComputeSignature(content, key))
	return plain
}

// readAll returns the stored value of every location (decrypted with key),
// plus whether the derived hashes match key.
func readAll(t *testing.T, db *sql.DB, key string) map[string]string {
	t.Helper()
	c, _ := crypto.NewCipherFromKey(key, "")
	dec := func(v string) string {
		p, err := c.DecryptString(strings.TrimPrefix(v, "enc:v1:"))
		if err != nil {
			return "<unreadable>"
		}
		return p
	}
	one := func(q string) string {
		t.Helper()
		var v sql.NullString
		if err := db.QueryRow(q).Scan(&v); err != nil {
			t.Fatalf("read %q: %v", q, err)
		}
		return v.String
	}
	out := map[string]string{}
	for loc, q := range map[string]string{
		"tenants.settings.ai.api_key":                         `SELECT settings #>> '{ai,api_key}' FROM tenants WHERE slug = 'rekey'`,
		"integrations.credentials_encrypted":                  `SELECT credentials_encrypted FROM integrations`,
		"integrations.metadata.webhook_secret_encrypted":      `SELECT metadata->>'webhook_secret_encrypted' FROM integrations`,
		"integration_scm_extensions.webhook_secret_encrypted": `SELECT convert_from(webhook_secret_encrypted, 'UTF8') FROM integration_scm_extensions`,
		"tenant_identity_providers.client_secret_encrypted":   `SELECT client_secret_encrypted FROM tenant_identity_providers`,
		"platform_identity_provider.client_secret_encrypted":  `SELECT client_secret_encrypted FROM platform_identity_provider`,
		"admin_idp_login_states.code_verifier_encrypted":      `SELECT code_verifier_encrypted FROM admin_idp_login_states`,
		"admin_credentials.mfa_secret_encrypted":              `SELECT mfa_secret_encrypted FROM admin_credentials`,
		"user_mfa.secret_encrypted":                           `SELECT secret_encrypted FROM user_mfa`,
		"user_mfa.pending_secret_encrypted":                   `SELECT pending_secret_encrypted FROM user_mfa`,
		"settings.value_json.access_key":                      `SELECT value_json->>'access_key' FROM settings WHERE key = 'storage_config'`,
		"settings.value_json.secret_key":                      `SELECT value_json->>'secret_key' FROM settings WHERE key = 'storage_config'`,
		"exposure_events.details.secret_value_enc":            `SELECT details->>'secret_value_enc' FROM exposure_events`,
	} {
		out[loc] = dec(one(q))
	}

	var fp string
	if err := db.QueryRow(`SELECT details->>'secret_fingerprint' FROM exposure_events`).Scan(&fp); err != nil {
		t.Fatal(err)
	}
	if fp != credential.NewSecretProtector(c, []byte(key)).Fingerprint(out["exposure_events.details.secret_value_enc"]) {
		out["exposure_events.details.secret_fingerprint"] = "<stale>"
	}

	var data []byte
	if err := db.QueryRow(`SELECT encrypted_data FROM credentials`).Scan(&data); err != nil {
		t.Fatal(err)
	}
	store, _ := secretstore.NewEncryptor(secretstore.KeyFromConfig(key))
	if p, err := store.Decrypt(data); err == nil {
		out["credentials.encrypted_data"] = string(p)
	} else {
		out["credentials.encrypted_data"] = "<unreadable>"
	}

	var content []byte
	var sig string
	if err := db.QueryRow(`SELECT content, signature_hash FROM scanner_templates`).Scan(&content, &sig); err != nil {
		t.Fatal(err)
	}
	if scannertemplate.VerifySignature(content, key, sig) {
		out["scanner_templates.signature_hash"] = string(content)
	} else {
		out["scanner_templates.signature_hash"] = "<unsigned>"
	}
	return out
}

func assertAll(t *testing.T, got, want map[string]string, label string) {
	t.Helper()
	for loc, w := range want {
		if got[loc] != w {
			t.Errorf("%s: %s = %q, want %q", label, loc, got[loc], w)
		}
	}
	if fp, ok := got["exposure_events.details.secret_fingerprint"]; ok {
		t.Errorf("%s: leaked-credential fingerprint is %s", label, fp)
	}
}

// Every registered location is populated under OLD. A dry run reports each
// one and leaves the database unchanged; -apply moves all of them to NEW in
// one go (fingerprint and template signature recomputed); a second run finds
// everything already under NEW and changes nothing.
func TestRekey_RoundTrip_DryRunApplyIdempotent(t *testing.T) {
	db := freshDB(t)
	ctx := context.Background()
	oldKey, newKey := randomHexKey(t), randomHexKey(t)
	want := seedAll(t, db, oldKey)
	keys := Keys{Old: oldKey, New: newKey}

	rep, err := Run(ctx, db, keys, Options{Sweep: true})
	if err != nil {
		t.Fatalf("dry run: %v (failures %+v, unlisted %+v)", err, rep.Failures, rep.Unlisted)
	}
	if rep.Committed {
		t.Fatal("a dry run must not commit")
	}
	for _, c := range rep.Counts {
		if c.Absent || c.Rekeyed != 1 || c.Already != 0 || c.Failed != 0 {
			t.Errorf("dry run %s: %+v, want exactly one value re-encrypted", c.Location, c)
		}
	}
	if n, _, _ := rep.Total(); n != len(registry) {
		t.Errorf("dry run re-encrypted %d values, want %d (one per location)", n, len(registry))
	}
	assertAll(t, readAll(t, db, oldKey), want, "after dry run (still OLD)")

	rep, err = Run(ctx, db, keys, Options{Apply: true, Sweep: true})
	if err != nil || !rep.Committed {
		t.Fatalf("apply: committed=%v err=%v", rep != nil && rep.Committed, err)
	}
	assertAll(t, readAll(t, db, newKey), want, "after apply (NEW)")

	rep, err = Run(ctx, db, keys, Options{Apply: true, Sweep: true})
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if r, a, f := rep.Total(); r != 0 || a != len(registry) || f != 0 {
		t.Errorf("second apply: rekeyed=%d already=%d failed=%d, want 0/%d/0", r, a, f, len(registry))
	}
	assertAll(t, readAll(t, db, newKey), want, "after second apply")
}

// One value neither key opens fails the run and rolls everything back.
func TestRekey_PartialFailureRollsBack(t *testing.T) {
	db := freshDB(t)
	ctx := context.Background()
	oldKey, newKey := randomHexKey(t), randomHexKey(t)
	want := seedAll(t, db, oldKey)

	stranger, _ := crypto.NewCipherFromKey(randomHexKey(t), "")
	bad, _ := stranger.EncryptString("not ours")
	// A second user whose TOTP secret neither key opens.
	if _, err := db.Exec(`INSERT INTO users (id, email) VALUES ('55555555-5555-7555-8555-555555555555', 'bad@example.com')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO user_mfa (user_id, secret_encrypted) VALUES ('55555555-5555-7555-8555-555555555555', $1)`, bad); err != nil {
		t.Fatal(err)
	}

	rep, err := Run(ctx, db, Keys{Old: oldKey, New: newKey}, Options{Apply: true, Sweep: true})
	if !errors.Is(err, ErrFailures) {
		t.Fatalf("expected ErrFailures, got %v", err)
	}
	if rep.Committed || len(rep.Failures) != 1 || rep.Failures[0].Location != "user_mfa.secret_encrypted" {
		t.Fatalf("expected one user_mfa failure and no commit, got committed=%v failures=%+v", rep.Committed, rep.Failures)
	}
	// Nothing moved, not even the locations processed before the failure.
	if _, err := db.Exec(`DELETE FROM user_mfa WHERE user_id = '55555555-5555-7555-8555-555555555555'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM users WHERE id = '55555555-5555-7555-8555-555555555555'`); err != nil {
		t.Fatal(err)
	}
	assertAll(t, readAll(t, db, oldKey), want, "after failed apply (still OLD)")
}

// OLD-key ciphertext in a column the registry does not know fails the run:
// a location added later cannot be silently left on the old key.
func TestRekey_SweepFindsUnlistedCiphertext(t *testing.T) {
	db := freshDB(t)
	ctx := context.Background()
	oldKey, newKey := randomHexKey(t), randomHexKey(t)
	seedAll(t, db, oldKey)

	c, _ := crypto.NewCipherFromKey(oldKey, "")
	hidden, _ := c.EncryptString("somewhere new")
	if _, err := db.Exec(`UPDATE tenants SET description = $1 WHERE slug = 'rekey'`, hidden); err != nil {
		t.Fatal(err)
	}

	rep, err := Run(ctx, db, Keys{Old: oldKey, New: newKey}, Options{Apply: true, Sweep: true})
	if !errors.Is(err, ErrFailures) || rep.Committed {
		t.Fatalf("expected ErrFailures without commit, got committed=%v err=%v", rep != nil && rep.Committed, err)
	}
	if len(rep.Unlisted) != 1 || rep.Unlisted[0].Location != "tenants.description" {
		t.Fatalf("expected tenants.description reported, got %+v", rep.Unlisted)
	}
}

func TestRekey_RefusesSameOrMissingKey(t *testing.T) {
	k := randomHexKey(t)
	for _, keys := range []Keys{{Old: k, New: k}, {Old: k}, {New: k}, {Old: "short", New: k}} {
		if _, err := Run(context.Background(), nil, keys, Options{}); err == nil {
			t.Errorf("Run(%+v) must refuse", Keys{OldFormat: keys.OldFormat})
		}
	}
}

// A value that cannot be AES-GCM output under any key (a 5-byte placeholder,
// as the live secret store holds) is reported and left alone, not counted as
// a failure: no key could ever open it, the server included.
func TestRekey_PlaceholderIsNotCiphertext(t *testing.T) {
	db := freshDB(t)
	ctx := context.Background()
	oldKey, newKey := randomHexKey(t), randomHexKey(t)
	want := seedAll(t, db, oldKey)
	if _, err := db.Exec(`INSERT INTO credentials (tenant_id, name, credential_type, encrypted_data)
		SELECT id, 'placeholder', 'bearer_token', '\xdeadbeef0a'::bytea FROM tenants WHERE slug = 'rekey'`); err != nil {
		t.Fatal(err)
	}

	rep, err := Run(ctx, db, Keys{Old: oldKey, New: newKey}, Options{Apply: true, Sweep: true})
	if err != nil || !rep.Committed {
		t.Fatalf("apply: committed=%v err=%v failures=%+v", rep != nil && rep.Committed, err, rep.Failures)
	}
	if len(rep.NotCipher) != 1 || rep.NotCipher[0].Location != "credentials.encrypted_data" {
		t.Fatalf("expected the placeholder listed as not ciphertext, got %+v", rep.NotCipher)
	}
	var raw []byte
	if err := db.QueryRow(`SELECT encrypted_data FROM credentials WHERE name = 'placeholder'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(raw) != "deadbeef0a" {
		t.Fatalf("placeholder changed: %x", raw)
	}
	if _, err := db.Exec(`DELETE FROM credentials WHERE name = 'placeholder'`); err != nil {
		t.Fatal(err)
	}
	assertAll(t, readAll(t, db, newKey), want, "after apply with a placeholder")
}
