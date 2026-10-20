package integration

// A CI job hashes each raw secret it finds with the key the exchange hands
// it (per organization and repository) and sends only the hash. A secret
// finding keyed on its masked value moves to that key without losing its
// triage; two different secrets with the same mask stay two findings; the
// key differs per repository.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/cirun"
)

func TestCISecretHash_KeepsIdentityWithoutTheRawValue(t *testing.T) {
	r := newCIRig(t)
	ctx := context.Background()
	cfg := r.trust(r.tenant, cirun.Rules{Owners: []string{"acme"}})
	host := strings.TrimPrefix(r.idp.srv.URL, "https://")
	repoName := strings.ToLower(host) + "/acme/api"

	exchange := func(project, job string) (id, tok string, key []byte) {
		t.Helper()
		_, ex := r.post("/api/v1/ci/oidc/exchange", "", map[string]string{"tenant_id": r.tenant.String(),
			"id_token": r.idp.token(t, cfg.Audience, project, "main", strings.Repeat(job, 40), map[string]any{"job_id": job})})
		k, err := base64.StdEncoding.DecodeString(ex["secret_key"].(string))
		if err != nil || len(k) != 32 {
			t.Fatalf("exchange gave no secret key: %v", ex)
		}
		return ex["run_id"].(string), ex["token"].(string), k
	}
	secret := func(raw string, key []byte) ctis.Finding {
		f := ciFinding("AWS key", "aws-access-key", "high", ctis.FindingTypeSecret, "config.go", 3)
		f.Secret = &ctis.SecretDetails{SecretType: "aws", MaskedValue: "AKIA****************WXYZ"}
		if key != nil {
			m := hmac.New(sha256.New, key)
			m.Write([]byte(raw))
			f.PartialFingerprints = map[string]string{"secretHMAC/v1": hex.EncodeToString(m.Sum(nil))}
		}
		return f
	}
	upload := func(id, tok string, fs ...ctis.Finding) {
		t.Helper()
		if resp, out := r.post("/api/v1/ci/runs/"+id+"/results", tok, ciReport(repoName, fs...)); resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload: %d %v", resp.StatusCode, out)
		}
	}
	count := func() int {
		var n int
		_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND finding_type = 'secret' AND status <> 'duplicate'`,
			r.tenant.String()).Scan(&n)
		return n
	}

	// An older job sent only the mask; the finding was marked a false positive.
	id, tok, key := exchange("acme/api", "1")
	upload(id, tok, secret("AKIAAAAAAAAAAAAAWXYZ", nil))
	if _, err := r.db.ExecContext(ctx, `UPDATE findings SET status = 'false_positive' WHERE tenant_id = $1 AND finding_type = 'secret'`,
		r.tenant.String()); err != nil {
		t.Fatal(err)
	}
	// The job now sends the keyed hash: the same finding, still a false positive.
	id, tok, key2 := exchange("acme/api", "2")
	if !hmac.Equal(key, key2) {
		t.Fatal("the key changed between runs of one repository")
	}
	upload(id, tok, secret("AKIAAAAAAAAAAAAAWXYZ", key))
	var status string
	_ = r.db.QueryRowContext(ctx, `SELECT status FROM findings WHERE tenant_id = $1 AND finding_type = 'secret' AND status <> 'duplicate'`,
		r.tenant.String()).Scan(&status)
	if count() != 1 || status != "false_positive" {
		t.Fatalf("after the hash: %d findings, status %q", count(), status)
	}
	// Another secret with the same mask is another finding.
	id, tok, _ = exchange("acme/api", "3")
	upload(id, tok, secret("AKIABBBBBBBBBBBBWXYZ", key))
	if count() != 2 {
		t.Fatalf("two secrets with one mask: %d findings, want 2", count())
	}
	// The raw value never reaches the platform.
	var leaked int
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND (row_to_json(findings)::text LIKE '%AKIAAAAAAAAAAAAAWXYZ%'
		OR row_to_json(findings)::text LIKE '%AKIABBBBBBBBBBBBWXYZ%')`, r.tenant.String()).Scan(&leaked)
	if leaked != 0 {
		t.Fatal("a raw secret was stored")
	}
	// The producer's keyed hash identified the finding but is not stored with it.
	var hashed int
	_ = r.db.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND finding_type = 'secret'
		AND partial_fingerprints::text ILIKE '%secrethmac%'`, r.tenant.String()).Scan(&hashed)
	if hashed != 0 {
		t.Fatalf("%d secret findings store the producer's keyed secret hash", hashed)
	}
	// Another repository gets another key.
	_, _, other := exchange("acme/web", "4")
	if hmac.Equal(other, key) {
		t.Fatal("two repositories share a secret key")
	}
}
