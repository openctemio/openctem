// Package rekey re-encrypts every value the platform stores under
// APP_ENCRYPTION_KEY with a new key, in one transaction (cmd/rekey).
//
// What the key protects, enumerated from the code (every EncryptString /
// secretstore / keyed-HMAC call site):
//
//	AES-256-GCM, base64 text (pkg/crypto.Cipher, the server's Encryptor):
//	  integrations.credentials_encrypted              integration credentials
//	  integrations.metadata.webhook_secret_encrypted  Jira webhook secret
//	  integration_scm_extensions.webhook_secret_encrypted (bytea of the text)
//	  tenant_identity_providers.client_secret_encrypted  organization SSO
//	  platform_identity_provider.client_secret_encrypted platform admin IdP
//	  admin_idp_login_states.code_verifier_encrypted  in-flight admin IdP logins
//	  admin_credentials.mfa_secret_encrypted          admin console TOTP
//	  user_mfa.secret_encrypted, pending_secret_encrypted  user TOTP
//	  settings.value_json.access_key / secret_key     tenant file storage (key 'storage_config')
//	  tenants.settings.ai.api_key                     BYOK LLM key ("enc:v1:" prefix)
//	  exposure_events.details.secret_value_enc        leaked-credential secret
//	AES-256-GCM, raw bytes (pkg/domain/secretstore, key = hex-decoded key):
//	  credentials.encrypted_data                      secret store (template sources, ...)
//	Keyed hashes that are recomputed from the plaintext:
//	  exposure_events.details.secret_fingerprint      HMAC keyed from the key
//	  scanner_templates.signature_hash                HMAC(key, content)
//
// Token hashes peppered with the key (oct_ API keys, SCIM tokens, sensor
// keys) are one-way and cannot be recomputed; the server keeps verifying
// them through APP_ENCRYPTION_KEY_PREVIOUS until those tokens are rotated.
//
// A value is re-encrypted when the OLD key opens it, skipped (and counted)
// when the NEW key already opens it, and otherwise reported as a failure; any
// failure rolls the whole transaction back. A sweep over every text, bytea
// and jsonb column also reports OLD-key ciphertext found anywhere this list
// does not cover, so a location added later cannot be silently left behind.
package rekey

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/credential"
	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/domain/secretstore"
)

// Keys holds both keys in the APP_ENCRYPTION_KEY string form.
type Keys struct {
	Old, OldFormat string
	New, NewFormat string
}

// Options controls a run.
type Options struct {
	// Apply commits the transaction; otherwise it is rolled back (dry run).
	Apply bool
	// Sweep scans every text/bytea/jsonb column for OLD-key ciphertext the
	// registry does not cover.
	Sweep bool
}

// Count is the outcome for one location.
type Count struct {
	Location string
	Rekeyed  int // opened with OLD, written under NEW
	Already  int // already under NEW, left as is
	Failed   int // opened by neither key
	// NotCipher counts values that cannot be AES-GCM output under any key
	// (not base64, or shorter than nonce + tag): placeholders or junk that
	// the server cannot read either. They are left as they are and listed.
	NotCipher int
	Absent    bool
}

// Failure names one value neither key opens.
type Failure struct {
	Location string
	Key      string // primary key of the row
	Reason   string
}

// Report is the result of a run.
type Report struct {
	Counts    []Count
	Failures  []Failure
	NotCipher []Failure // values that are not ciphertext at all (left unchanged)
	Unlisted  []Failure // sweep: OLD-key ciphertext outside the registry
	Committed bool
}

// Total returns the number of values re-encrypted.
func (r *Report) Total() (rekeyed, already, failed int) {
	for _, c := range r.Counts {
		rekeyed += c.Rekeyed
		already += c.Already
		failed += c.Failed
	}
	return
}

const notCipherReason = "not ciphertext under any key (too short or not base64); left unchanged"

// ErrFailures is returned when a value could not be opened with either key,
// or the sweep found unlisted ciphertext; nothing is committed.
var ErrFailures = errors.New("rekey: values that neither key opens (nothing committed)")

type keyset struct {
	oldC, newC         *crypto.Cipher
	oldStore, newStore *secretstore.Encryptor
	oldRaw, newRaw     string
	newProtector       *credential.SecretProtector
}

func newKeyset(k Keys) (*keyset, error) {
	if k.Old == "" || k.New == "" {
		return nil, errors.New("rekey: both the old and the new key are required")
	}
	if k.Old == k.New {
		return nil, errors.New("rekey: the new key equals the old key")
	}
	oldC, err := crypto.NewCipherFromKey(k.Old, k.OldFormat)
	if err != nil {
		return nil, fmt.Errorf("rekey: old key: %w", err)
	}
	newC, err := crypto.NewCipherFromKey(k.New, k.NewFormat)
	if err != nil {
		return nil, fmt.Errorf("rekey: new key: %w", err)
	}
	ks := &keyset{oldC: oldC, newC: newC, oldRaw: k.Old, newRaw: k.New,
		newProtector: credential.NewSecretProtector(newC, []byte(k.New))}
	// The secret store derives its key separately (hex-decoded, else raw
	// bytes); a key that does not yield 32 bytes there leaves it unusable on
	// the server too, so the store is simply skipped.
	if s, err := secretstore.NewEncryptor(secretstore.KeyFromConfig(k.Old)); err == nil {
		ks.oldStore = s
	}
	if s, err := secretstore.NewEncryptor(secretstore.KeyFromConfig(k.New)); err == nil {
		ks.newStore = s
	}
	return ks, nil
}

// reseal re-encrypts a base64 Cipher value: (new value, outcome).
func (ks *keyset) reseal(v string) (string, outcome) {
	if !isCipherText(v) {
		return "", notCipher
	}
	if p, err := ks.oldC.DecryptString(v); err == nil {
		out, err := ks.newC.EncryptString(p)
		if err != nil {
			return "", failed
		}
		return out, rekeyed
	}
	if _, err := ks.newC.DecryptString(v); err == nil {
		return v, already
	}
	return "", failed
}

type outcome int

const (
	failed outcome = iota
	rekeyed
	already
	notCipher
)

// isCipherText reports whether v can be base64 AES-GCM output at all.
func isCipherText(v string) bool {
	raw, err := base64.StdEncoding.DecodeString(v)
	return err == nil && len(raw) >= minCipherBytes
}

// Run re-encrypts every registered location inside one transaction.
func Run(ctx context.Context, db *sql.DB, k Keys, opt Options) (*Report, error) {
	ks, err := newKeyset(k)
	if err != nil {
		return nil, err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, fmt.Errorf("rekey: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rep := &Report{}
	for _, loc := range registry {
		c, fails, err := loc.run(ctx, tx, ks)
		if err != nil {
			return nil, fmt.Errorf("rekey: %s: %w", loc.name(), err)
		}
		rep.Counts = append(rep.Counts, c)
		for _, f := range fails {
			if f.Reason == notCipherReason {
				rep.NotCipher = append(rep.NotCipher, f)
			} else {
				rep.Failures = append(rep.Failures, f)
			}
		}
	}
	if opt.Sweep {
		unlisted, err := sweep(ctx, tx, ks)
		if err != nil {
			return nil, fmt.Errorf("rekey: sweep: %w", err)
		}
		rep.Unlisted = unlisted
	}
	if len(rep.Failures) > 0 || len(rep.Unlisted) > 0 {
		return rep, ErrFailures
	}
	if !opt.Apply {
		return rep, nil
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("rekey: commit: %w", err)
	}
	rep.Committed = true
	return rep, nil
}

// location is one place a key-protected value lives.
type location interface {
	name() string
	run(ctx context.Context, tx *sql.Tx, ks *keyset) (Count, []Failure, error)
}

var registry = []location{
	textCol{table: "integrations", pk: "id", col: "credentials_encrypted"},
	jsonField{table: "integrations", pk: "id", col: "metadata", path: []string{"webhook_secret_encrypted"}},
	textCol{table: "integration_scm_extensions", pk: "integration_id", col: "webhook_secret_encrypted", bytea: true},
	textCol{table: "tenant_identity_providers", pk: "id", col: "client_secret_encrypted"},
	textCol{table: "platform_identity_provider", pk: "id", col: "client_secret_encrypted"},
	textCol{table: "admin_idp_login_states", pk: "state_hash", col: "code_verifier_encrypted"},
	textCol{table: "admin_credentials", pk: "admin_id", col: "mfa_secret_encrypted"},
	textCol{table: "user_mfa", pk: "user_id", col: "secret_encrypted"},
	textCol{table: "user_mfa", pk: "user_id", col: "pending_secret_encrypted"},
	jsonField{table: "settings", pk: "id", col: "value_json", path: []string{"access_key"}, where: "key = 'storage_config'"},
	jsonField{table: "settings", pk: "id", col: "value_json", path: []string{"secret_key"}, where: "key = 'storage_config'"},
	jsonField{table: "tenants", pk: "id", col: "settings", path: []string{"ai", "api_key"}, prefix: "enc:v1:"},
	leakedSecret{},
	secretStore{},
	templateSignature{},
}

func columnExists(ctx context.Context, tx *sql.Tx, table, col string) (bool, error) {
	var ok bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2)`, table, col).Scan(&ok)
	return ok, err
}

// pgIdent quotes an identifier from the fixed registry (never user input).
func pgIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// keyed is one row: its primary key and the stored value.
type keyed struct {
	pk string
	v  []byte
}

// collect runs q (two columns: primary key as text, value) and returns the
// rows with the cursor closed, so updates can follow on the same transaction.
func collect(ctx context.Context, tx *sql.Tx, q string, args ...any) ([]keyed, error) {
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []keyed
	for rows.Next() {
		var r keyed
		if err := rows.Scan(&r.pk, &r.v); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// tally records the outcome of one value.
func tally(cnt *Count, fails *[]Failure, loc, pk string, oc outcome) {
	switch oc {
	case rekeyed:
		cnt.Rekeyed++
	case already:
		cnt.Already++
	case notCipher:
		cnt.NotCipher++
		*fails = append(*fails, Failure{Location: loc, Key: pk, Reason: notCipherReason})
	default:
		cnt.Failed++
		*fails = append(*fails, Failure{Location: loc, Key: pk, Reason: "opened by neither key"})
	}
}

// textCol is a column holding base64 Cipher text (or bytea of that text).
type textCol struct {
	table, pk, col string
	bytea          bool
}

func (c textCol) name() string { return c.table + "." + c.col }

func (c textCol) run(ctx context.Context, tx *sql.Tx, ks *keyset) (Count, []Failure, error) {
	cnt := Count{Location: c.name()}
	ok, err := columnExists(ctx, tx, c.table, c.col)
	if err != nil || !ok {
		cnt.Absent = !ok
		return cnt, nil, err
	}
	//nolint:gosec // G201: identifiers come from the fixed registry, quoted by pgIdent
	sel := fmt.Sprintf(`SELECT %s::text, %s FROM %s WHERE %s IS NOT NULL FOR UPDATE`,
		pgIdent(c.pk), pgIdent(c.col), pgIdent(c.table), pgIdent(c.col))
	rows, err := collect(ctx, tx, sel)
	if err != nil {
		return cnt, nil, err
	}
	set := "$1"
	if c.bytea {
		set = "convert_to($1, 'UTF8')"
	}
	//nolint:gosec // G201: identifiers come from the fixed registry, quoted by pgIdent
	stmt := fmt.Sprintf(`UPDATE %s SET %s = %s WHERE %s::text = $2`, pgIdent(c.table), pgIdent(c.col), set, pgIdent(c.pk))
	var fails []Failure
	for _, r := range rows {
		if len(r.v) == 0 {
			continue
		}
		out, oc := ks.reseal(string(r.v))
		tally(&cnt, &fails, c.name(), r.pk, oc)
		if oc == rekeyed {
			if _, err := tx.ExecContext(ctx, stmt, out, r.pk); err != nil {
				return cnt, nil, err
			}
		}
	}
	return cnt, fails, nil
}

// jsonField is a string at path inside a jsonb column.
type jsonField struct {
	table, pk, col string
	path           []string
	where          string // extra fixed predicate from the registry
	prefix         string // value prefix kept around the ciphertext
}

func (j jsonField) name() string { return j.table + "." + j.col + "." + strings.Join(j.path, ".") }

func (j jsonField) run(ctx context.Context, tx *sql.Tx, ks *keyset) (Count, []Failure, error) {
	cnt := Count{Location: j.name()}
	ok, err := columnExists(ctx, tx, j.table, j.col)
	if err != nil || !ok {
		cnt.Absent = !ok
		return cnt, nil, err
	}
	pathLit := "{" + strings.Join(j.path, ",") + "}"
	where := fmt.Sprintf("%s #>> '%s' IS NOT NULL", pgIdent(j.col), pathLit)
	if j.where != "" {
		where += " AND " + j.where
	}
	//nolint:gosec // G201: identifiers and paths come from the fixed registry
	sel := fmt.Sprintf(`SELECT %s::text, %s #>> '%s' FROM %s WHERE %s FOR UPDATE`,
		pgIdent(j.pk), pgIdent(j.col), pathLit, pgIdent(j.table), where)
	rows, err := collect(ctx, tx, sel)
	if err != nil {
		return cnt, nil, err
	}
	//nolint:gosec // G201: identifiers and paths come from the fixed registry
	stmt := fmt.Sprintf(`UPDATE %s SET %s = jsonb_set(%s, '%s', to_jsonb($1::text)) WHERE %s::text = $2`,
		pgIdent(j.table), pgIdent(j.col), pgIdent(j.col), pathLit, pgIdent(j.pk))
	var fails []Failure
	for _, r := range rows {
		v := string(r.v)
		if v == "" {
			continue
		}
		if j.prefix != "" {
			if !strings.HasPrefix(v, j.prefix) {
				continue // stored without encryption (legacy plaintext): not ours to touch
			}
			v = strings.TrimPrefix(v, j.prefix)
		}
		out, oc := ks.reseal(v)
		tally(&cnt, &fails, j.name(), r.pk, oc)
		if oc == rekeyed {
			if _, err := tx.ExecContext(ctx, stmt, j.prefix+out, r.pk); err != nil {
				return cnt, nil, err
			}
		}
	}
	return cnt, fails, nil
}

// leakedSecret is the sealed secret in exposure_events.details plus its
// keyed fingerprint, which is recomputed under the new key.
type leakedSecret struct{}

func (leakedSecret) name() string { return "exposure_events.details.secret_value_enc" }

func (l leakedSecret) run(ctx context.Context, tx *sql.Tx, ks *keyset) (Count, []Failure, error) {
	cnt := Count{Location: l.name()}
	ok, err := columnExists(ctx, tx, "exposure_events", "details")
	if err != nil || !ok {
		cnt.Absent = !ok
		return cnt, nil, err
	}
	rows, err := collect(ctx, tx, `SELECT id::text, details->>'secret_value_enc' FROM exposure_events
		WHERE details->>'secret_value_enc' IS NOT NULL AND details->>'secret_enc_scheme' = $1 FOR UPDATE`,
		credential.SecretSchemeAESGCM)
	if err != nil {
		return cnt, nil, err
	}
	var fails []Failure
	for _, r := range rows {
		v := string(r.v)
		oc := failed
		var out, fp string
		switch {
		case !isCipherText(v):
			oc = notCipher
		default:
			if p, err := ks.oldC.DecryptString(v); err == nil {
				if out, err = ks.newC.EncryptString(p); err != nil {
					return cnt, nil, err
				}
				fp, oc = ks.newProtector.Fingerprint(p), rekeyed
			} else if _, err := ks.newC.DecryptString(v); err == nil {
				oc = already
			}
		}
		tally(&cnt, &fails, l.name(), r.pk, oc)
		if oc == rekeyed {
			if _, err := tx.ExecContext(ctx, `UPDATE exposure_events
				SET details = jsonb_set(jsonb_set(details, '{secret_value_enc}', to_jsonb($1::text)),
				                        '{secret_fingerprint}', to_jsonb($2::text))
				WHERE id::text = $3`, out, fp, r.pk); err != nil {
				return cnt, nil, err
			}
		}
	}
	return cnt, fails, nil
}

// secretStore is credentials.encrypted_data (raw AES-GCM bytes).
type secretStore struct{}

func (secretStore) name() string { return "credentials.encrypted_data" }

func (s secretStore) run(ctx context.Context, tx *sql.Tx, ks *keyset) (Count, []Failure, error) {
	cnt := Count{Location: s.name()}
	ok, err := columnExists(ctx, tx, "credentials", "encrypted_data")
	if err != nil || !ok {
		cnt.Absent = !ok
		return cnt, nil, err
	}
	rows, err := collect(ctx, tx, `SELECT id::text, encrypted_data FROM credentials WHERE encrypted_data IS NOT NULL FOR UPDATE`)
	if err != nil {
		return cnt, nil, err
	}
	var fails []Failure
	for _, r := range rows {
		if len(r.v) == 0 {
			continue
		}
		oc := failed
		var out []byte
		switch {
		case len(r.v) < minCipherBytes:
			oc = notCipher
		case ks.oldStore != nil && ks.newStore != nil:
			if p, err := ks.oldStore.Decrypt(r.v); err == nil {
				if out, err = ks.newStore.Encrypt(p); err != nil {
					return cnt, nil, err
				}
				oc = rekeyed
			} else if _, err := ks.newStore.Decrypt(r.v); err == nil {
				oc = already
			}
		}
		tally(&cnt, &fails, s.name(), r.pk, oc)
		if oc == rekeyed {
			if _, err := tx.ExecContext(ctx, `UPDATE credentials SET encrypted_data = $1 WHERE id::text = $2`, out, r.pk); err != nil {
				return cnt, nil, err
			}
		}
	}
	return cnt, fails, nil
}

// templateSignature re-signs scanner_templates.signature_hash under the new key.
type templateSignature struct{}

func (templateSignature) name() string { return "scanner_templates.signature_hash" }

func (t templateSignature) run(ctx context.Context, tx *sql.Tx, ks *keyset) (Count, []Failure, error) {
	cnt := Count{Location: t.name()}
	ok, err := columnExists(ctx, tx, "scanner_templates", "signature_hash")
	if err != nil || !ok {
		cnt.Absent = !ok
		return cnt, nil, err
	}
	sigs, err := collect(ctx, tx, `SELECT id::text, convert_to(signature_hash, 'UTF8') FROM scanner_templates
		WHERE signature_hash IS NOT NULL AND signature_hash <> '' FOR UPDATE`)
	if err != nil {
		return cnt, nil, err
	}
	var fails []Failure
	for _, r := range sigs {
		var content []byte
		if err := tx.QueryRowContext(ctx, `SELECT content FROM scanner_templates WHERE id::text = $1`, r.pk).Scan(&content); err != nil {
			return cnt, nil, err
		}
		sig := string(r.v)
		oc := failed
		switch {
		case scannertemplate.VerifySignature(content, ks.oldRaw, sig):
			oc = rekeyed
		case scannertemplate.VerifySignature(content, ks.newRaw, sig):
			oc = already
		}
		if oc == failed {
			cnt.Failed++
			fails = append(fails, Failure{Location: t.name(), Key: r.pk, Reason: "signature matches neither key"})
			continue
		}
		tally(&cnt, &fails, t.name(), r.pk, oc)
		if oc == rekeyed {
			if _, err := tx.ExecContext(ctx, `UPDATE scanner_templates SET signature_hash = $1 WHERE id::text = $2`,
				scannertemplate.ComputeSignature(content, ks.newRaw), r.pk); err != nil {
				return cnt, nil, err
			}
		}
	}
	return cnt, fails, nil
}

// minCipherBytes is nonce (12) + GCM tag (16): anything shorter is not ours.
const minCipherBytes = 28

// sweep looks through every text, bytea and jsonb column for values the OLD
// key still opens. It runs after the registry pass in the same transaction,
// so every registered value is already under NEW and anything the OLD key
// still opens is in a place the registry does not cover.
func sweep(ctx context.Context, tx *sql.Tx, ks *keyset) ([]Failure, error) {
	type colRef struct{ table, col, typ string }
	listCols := func() ([]colRef, error) {
		rows, err := tx.QueryContext(ctx, `SELECT c.table_name, c.column_name, c.data_type
			FROM information_schema.columns c
			JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name
			WHERE c.table_schema = current_schema() AND t.table_type = 'BASE TABLE'
			  AND c.data_type IN ('text', 'character varying', 'bytea', 'jsonb', 'json')
			ORDER BY 1, 2`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var cols []colRef
		for rows.Next() {
			var c colRef
			if err := rows.Scan(&c.table, &c.col, &c.typ); err != nil {
				return nil, err
			}
			cols = append(cols, c)
		}
		return cols, rows.Err()
	}
	cols, err := listCols()
	if err != nil {
		return nil, err
	}

	found := map[string]int{}
	for _, c := range cols {
		// Identifiers come from information_schema and are quoted.
		//nolint:gosec // G201: quoted catalog identifiers, no user input
		q := fmt.Sprintf(`SELECT '', %s::text FROM %s WHERE %s IS NOT NULL`, pgIdent(c.col), pgIdent(c.table), pgIdent(c.col))
		if c.typ == "bytea" {
			//nolint:gosec // G201: quoted catalog identifiers, no user input
			q = fmt.Sprintf(`SELECT '', %s FROM %s WHERE length(%s) >= %d`,
				pgIdent(c.col), pgIdent(c.table), pgIdent(c.col), minCipherBytes)
		}
		vals, err := collect(ctx, tx, q)
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %w", c.table, c.col, err)
		}
		for _, r := range vals {
			n := 0
			switch c.typ {
			case "jsonb", "json":
				var doc any
				if json.Unmarshal(r.v, &doc) == nil {
					n = countOldInJSON(doc, ks)
				}
			case "bytea":
				if ks.opensOld(string(r.v)) || (ks.oldStore != nil && opensStore(ks.oldStore, r.v)) {
					n = 1
				}
			default:
				if ks.opensOld(string(r.v)) {
					n = 1
				}
			}
			found[c.table+"."+c.col] += n
		}
	}
	out := make([]Failure, 0, len(found))
	for loc, n := range found {
		if n == 0 {
			continue
		}
		out = append(out, Failure{Location: loc, Key: fmt.Sprintf("%d value(s)", n),
			Reason: "OLD-key ciphertext in a location cmd/rekey does not cover"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Location < out[j].Location })
	return out, nil
}

func (ks *keyset) opensOld(v string) bool {
	v = strings.TrimPrefix(v, "enc:v1:")
	if len(v) < 40 { // base64 of minCipherBytes
		return false
	}
	_, err := ks.oldC.DecryptString(v)
	return err == nil
}

func opensStore(e *secretstore.Encryptor, raw []byte) bool {
	if len(raw) < minCipherBytes {
		return false
	}
	_, err := e.Decrypt(raw)
	return err == nil
}

func countOldInJSON(doc any, ks *keyset) int {
	switch v := doc.(type) {
	case string:
		if ks.opensOld(v) {
			return 1
		}
	case map[string]any:
		n := 0
		for _, x := range v {
			n += countOldInJSON(x, ks)
		}
		return n
	case []any:
		n := 0
		for _, x := range v {
			n += countOldInJSON(x, ks)
		}
		return n
	}
	return 0
}
