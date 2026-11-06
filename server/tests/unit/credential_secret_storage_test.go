package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/integration"
	"github.com/openctemio/openctem/server/pkg/domain/credential"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// storagePolicy is a per-organization storage decision for the tests.
type storagePolicy map[shared.ID]bool

func (p storagePolicy) StoresSecretValues(_ context.Context, tenantID shared.ID) bool {
	return p[tenantID]
}

func importSecret(t *testing.T, svc *integration.CredentialImportService, tenantID shared.ID, secret string, strategy credential.DedupStrategy) *credential.ImportResult {
	t.Helper()
	cred := validCredentialImport()
	cred.SecretValue = secret
	req := validImportRequest(cred)
	if strategy != "" {
		req.Options.DedupStrategy = strategy
	}
	res, err := svc.Import(context.Background(), tenantID.String(), req)
	if err != nil || len(res.Errors) != 0 {
		t.Fatalf("import: err=%v res=%+v", err, res)
	}
	return res
}

// An organization that does not keep secret values gets the mask, the type
// and its fingerprint only; nothing is revealable. Another organization's
// choice (keep) does not change it, and the same secret in the two
// organizations has two different fingerprints.
func TestCredentialImport_StoreOffKeepsNoValue_PerTenant(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	p := testProtector(t, testEncKeyHex)
	svc.SetSecretProtector(p)
	off, on := shared.NewID(), shared.NewID()
	svc.SetStoragePolicy(storagePolicy{off: false, on: true})

	offRes := importSecret(t, svc, off, leakedSecretForTest, "")
	onRes := importSecret(t, svc, on, leakedSecretForTest, "")

	offDetails := repo.events[offRes.Details[0].ID].Details()
	for _, k := range []string{credential.DetailSecretValue, credential.DetailSecretCiphertext, credential.DetailSecretScheme} {
		if _, ok := offDetails[k]; ok {
			t.Fatalf("store off kept %s: %v", k, offDetails)
		}
	}
	if offDetails[credential.DetailSecretMasked] == nil || offDetails["credential_type"] != "password" ||
		offDetails[credential.DetailSecretFingerprint] != p.Fingerprint(off, leakedSecretForTest) {
		t.Fatalf("store off must keep mask, type and the organization's fingerprint: %v", offDetails)
	}
	if _, err := svc.RevealSecret(context.Background(), off.String(), offRes.Details[0].ID); !errors.Is(err, integration.ErrNoSecret) {
		t.Fatalf("reveal with nothing stored: %v", err)
	}

	onDetails := repo.events[onRes.Details[0].ID].Details()
	if _, ok := onDetails[credential.DetailSecretCiphertext]; !ok {
		t.Fatalf("store on must keep the sealed value: %v", onDetails)
	}
	got, err := svc.RevealSecret(context.Background(), on.String(), onRes.Details[0].ID)
	if err != nil || got != leakedSecretForTest {
		t.Fatalf("reveal: %q %v", got, err)
	}
	if onDetails[credential.DetailSecretFingerprint] == offDetails[credential.DetailSecretFingerprint] {
		t.Fatal("cross-tenant: the same secret must not have the same fingerprint")
	}
	// Cross-tenant reveal: the other organization's id answers not found.
	if _, err := svc.RevealSecret(context.Background(), off.String(), onRes.Details[0].ID); err == nil {
		t.Fatal("cross-tenant reveal must fail")
	}
}

// An organization that turned storage off: a re-import with a new value
// drops the ciphertext of the old one (it would be revealable next to the
// new mask and fingerprint).
func TestCredentialImport_StoreTurnedOffDropsOldCiphertextOnUpdate(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	p := testProtector(t, testEncKeyHex)
	svc.SetSecretProtector(p)
	tenantID := shared.NewID()
	policy := storagePolicy{tenantID: true}
	svc.SetStoragePolicy(policy)

	first := importSecret(t, svc, tenantID, "old-secret", "")
	id := first.Details[0].ID
	if _, ok := repo.events[id].Details()[credential.DetailSecretCiphertext]; !ok {
		t.Fatal("fixture: value kept while storage is on")
	}
	policy[tenantID] = false
	importSecret(t, svc, tenantID, "new-secret", credential.DedupStrategyUpdateAll)
	d := repo.events[id].Details()
	if credential.HasSecret(d) {
		t.Fatalf("old ciphertext kept after storage was turned off: %v", d)
	}
	if d[credential.DetailSecretFingerprint] != p.Fingerprint(tenantID, "new-secret") {
		t.Fatalf("fingerprint of the new value expected: %v", d)
	}
}

// Without a policy (an unwired service) the value is kept, as before.
func TestCredentialImport_NoPolicyKeepsValue(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	svc.SetSecretProtector(testProtector(t, testEncKeyHex))
	res := importSecret(t, svc, shared.NewID(), leakedSecretForTest, "")
	if !credential.HasSecret(repo.events[res.Details[0].ID].Details()) {
		t.Fatal("unwired service must keep the value")
	}
}
