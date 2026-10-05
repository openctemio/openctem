package unit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/app/exposure"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/credential"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The raw leaked secret must never come back from the read endpoints that the
// Viewer role can reach (findings:credentials:read). It is returned only by the
// dedicated, audited reveal path.
const leakedSecretForTest = "Sup3r-Secret-Leaked-Passw0rd!"

func importLeakedSecret(t *testing.T, svc *app.CredentialImportService, tenantID shared.ID) string {
	t.Helper()
	cred := validCredentialImport()
	cred.SecretValue = leakedSecretForTest
	res, err := svc.Import(context.Background(), tenantID.String(), validImportRequest(cred))
	if err != nil || res.Imported != 1 {
		t.Fatalf("import: err=%v res=%+v", err, res)
	}
	return res.Details[0].ID
}

func assertNoPlaintext(t *testing.T, what string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %s: %v", what, err)
	}
	if strings.Contains(string(b), leakedSecretForTest) {
		t.Errorf("%s returns the plaintext leaked secret: %s", what, b)
	}
}

func TestCredentialReadPaths_DoNotReturnPlaintextSecret(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()
	id := importLeakedSecret(t, svc, tenantID)
	ctx := context.Background()

	list, err := svc.List(ctx, tenantID.String(), app.CredentialListOptions{}, 1, 20)
	if err != nil {
		t.Fatal(err)
	}
	assertNoPlaintext(t, "List", list)

	item, err := svc.GetByID(ctx, tenantID.String(), id)
	if err != nil {
		t.Fatal(err)
	}
	assertNoPlaintext(t, "GetByID", item)

	byIdentity, err := svc.GetExposuresForIdentity(ctx, tenantID.String(), "user@example.com", 1, 20)
	if err != nil {
		t.Fatal(err)
	}
	assertNoPlaintext(t, "GetExposuresForIdentity", byIdentity)
}

const testEncKeyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

func testProtector(t *testing.T, keyHex string) *credential.SecretProtector {
	t.Helper()
	c, err := crypto.NewCipherFromHex(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	return credential.NewSecretProtector(c, []byte(keyHex))
}

func TestSecretProtector_SealOpenRoundTrip(t *testing.T) {
	p := testProtector(t, testEncKeyHex)
	details := map[string]any{credential.DetailSecretValue: leakedSecretForTest, "email": "a@b.c"}
	if err := p.Seal(details); err != nil {
		t.Fatal(err)
	}
	if _, ok := details[credential.DetailSecretValue]; ok {
		t.Fatal("plaintext key must be removed after sealing")
	}
	ct, _ := details[credential.DetailSecretCiphertext].(string)
	if ct == "" || strings.Contains(ct, leakedSecretForTest) {
		t.Fatalf("expected ciphertext, got %q", ct)
	}
	if details[credential.DetailSecretScheme] != credential.SecretSchemeAESGCM {
		t.Fatalf("scheme = %v", details[credential.DetailSecretScheme])
	}
	got, ok, err := p.Open(details)
	if err != nil || !ok || got != leakedSecretForTest {
		t.Fatalf("Open = %q %v %v", got, ok, err)
	}
	if details[credential.DetailSecretFingerprint] != p.Fingerprint(leakedSecretForTest) {
		t.Fatal("fingerprint must be the keyed fingerprint of the secret")
	}
	other := testProtector(t, strings.Repeat("ab", 32))
	if other.Fingerprint(leakedSecretForTest) == p.Fingerprint(leakedSecretForTest) {
		t.Fatal("fingerprint must depend on the platform key (not a plain hash)")
	}
	if _, _, err := other.Open(details); !errors.Is(err, credential.ErrSecretUnreadable) {
		t.Fatalf("a different key must not open the secret, err=%v", err)
	}
}

func TestSecretProtector_LegacyPlaintextRowStaysReadableAndIsMasked(t *testing.T) {
	p := testProtector(t, testEncKeyHex)
	legacy := map[string]any{credential.DetailSecretValue: "hunter2", "username": "bob"}
	got, ok, err := p.Open(legacy)
	if err != nil || !ok || got != "hunter2" {
		t.Fatalf("legacy Open = %q %v %v", got, ok, err)
	}
	safe := credential.RedactDetails(legacy)
	if _, leaked := safe[credential.DetailSecretValue]; leaked {
		t.Fatal("RedactDetails must drop the legacy plaintext")
	}
	if safe[credential.DetailSecretMasked] != "********" || safe["username"] != "bob" {
		t.Fatalf("unexpected redaction: %v", safe)
	}
	if legacy[credential.DetailSecretValue] != "hunter2" {
		t.Fatal("RedactDetails must not modify its input")
	}
	if !p.NeedsSealing(legacy) {
		t.Fatal("a legacy row needs sealing")
	}
	if err := p.Seal(legacy); err != nil || p.NeedsSealing(legacy) {
		t.Fatalf("sealing is idempotent: err=%v needs=%v", err, p.NeedsSealing(legacy))
	}
}

func TestSecretProtector_NoKeyRowsAreResealedOnceAKeyExists(t *testing.T) {
	dev := credential.NewSecretProtector(nil, nil)
	details := map[string]any{credential.DetailSecretValue: "dev-secret"}
	if err := dev.Seal(details); err != nil {
		t.Fatal(err)
	}
	if details[credential.DetailSecretScheme] != credential.SecretSchemeNone {
		t.Fatalf("no-key scheme = %v", details[credential.DetailSecretScheme])
	}
	if dev.NeedsSealing(details) {
		t.Fatal("without a key there is nothing more to do")
	}
	prod := testProtector(t, testEncKeyHex)
	if !prod.NeedsSealing(details) {
		t.Fatal("with a key, a scheme=none row must be resealed")
	}
	if err := prod.Seal(details); err != nil {
		t.Fatal(err)
	}
	if details[credential.DetailSecretCiphertext] == "dev-secret" || details[credential.DetailSecretScheme] != credential.SecretSchemeAESGCM {
		t.Fatalf("not resealed: %v", details)
	}
	if got, _, err := prod.Open(details); err != nil || got != "dev-secret" {
		t.Fatalf("Open after reseal = %q %v", got, err)
	}
}

func TestMaskSecret(t *testing.T) {
	cases := []struct{ typ, in, want string }{
		{"password", "", ""},
		{"password", "hunter2", "********"},
		{"password", "a-very-long-passphrase-of-many-words", "********"},
		{"private_key", "-----BEGIN OPENSSH PRIVATE KEY-----", "********"},
		{"api_key", "short-key", "********"},
		{"aws_key", "AKIAIOSFODNN7EXAMPLE", "AKIA********"},
		{"access_token", "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ghp_********"},
	}
	for _, c := range cases {
		if got := credential.MaskSecret(c.typ, c.in); got != c.want {
			t.Errorf("MaskSecret(%q, %q) = %q, want %q", c.typ, c.in, got, c.want)
		}
	}
}

func TestCredentialImport_SecretIsEncryptedAtRest_AndRevealIsTenantScoped(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	svc.SetSecretProtector(testProtector(t, testEncKeyHex))
	tenantID := shared.NewID()
	id := importLeakedSecret(t, svc, tenantID)

	stored := repo.events[id].Details()
	raw, _ := json.Marshal(stored)
	if strings.Contains(string(raw), leakedSecretForTest) {
		t.Fatalf("plaintext stored at rest: %s", raw)
	}
	if stored[credential.DetailSecretScheme] != credential.SecretSchemeAESGCM {
		t.Fatalf("expected AES-GCM at rest, got %v", stored[credential.DetailSecretScheme])
	}

	item, err := svc.GetByID(context.Background(), tenantID.String(), id)
	if err != nil {
		t.Fatal(err)
	}
	if !item.HasSecret || item.SecretMasked != "********" || item.SecretFingerprint == "" {
		t.Fatalf("read view: has=%v mask=%q fp=%q", item.HasSecret, item.SecretMasked, item.SecretFingerprint)
	}

	got, err := svc.RevealSecret(context.Background(), tenantID.String(), id)
	if err != nil || got != leakedSecretForTest {
		t.Fatalf("RevealSecret = %q %v", got, err)
	}
	if _, err := svc.RevealSecret(context.Background(), shared.NewID().String(), id); err == nil {
		t.Fatal("another tenant must not reveal this secret")
	}
}

func TestCredentialImport_RevealWithoutStoredSecret(t *testing.T) {
	svc, _, _ := newCredImportTestService()
	tenantID := shared.NewID()
	res, err := svc.Import(context.Background(), tenantID.String(), validImportRequest())
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.RevealSecret(context.Background(), tenantID.String(), res.Details[0].ID)
	if !errors.Is(err, app.ErrCredentialNoSecret) {
		t.Fatalf("expected ErrCredentialNoSecret, got %v", err)
	}
}

func TestCredentialImport_UpdateAllReplacesLegacyPlaintext(t *testing.T) {
	svc, repo, _ := newCredImportTestService()
	svc.SetSecretProtector(testProtector(t, testEncKeyHex))
	tenantID := shared.NewID()
	cred := validCredentialImport()
	cred.SecretValue = leakedSecretForTest

	// A row written before encryption: plaintext under secret_value, same
	// fingerprint as the incoming import.
	legacy := createCredImportTestEvent(tenantID, cred.Identifier, cred.GetSourceString())
	legacy.SetDetail(credential.DetailSecretValue, "old-plaintext")
	repo.events[legacy.ID().String()] = legacy
	repo.fingerprintMap[cred.CalculateFingerprint(tenantID.String())] = legacy

	req := validImportRequest(cred)
	req.Options.DedupStrategy = credential.DedupStrategyUpdateAll
	if _, err := svc.Import(context.Background(), tenantID.String(), req); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(legacy.Details())
	if strings.Contains(string(raw), "old-plaintext") || strings.Contains(string(raw), leakedSecretForTest) {
		t.Fatalf("plaintext survived the update: %s", raw)
	}
}

func TestExposureService_SealsSecretsFromGenericEndpoints(t *testing.T) {
	repo := newCredImportMockExposureRepo()
	svc := exposure.NewExposureService(repo, newCredImportMockStateHistoryRepo(), logger.NewNop())
	svc.SetSecretProtector(testProtector(t, testEncKeyHex))
	ev, err := svc.CreateExposure(context.Background(), exposure.CreateExposureInput{
		TenantID:  shared.NewID().String(),
		EventType: "credential_leaked",
		Severity:  "high",
		Title:     "leak",
		Source:    "manual",
		Details:   map[string]any{credential.DetailSecretValue: leakedSecretForTest},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(ev.Details())
	if strings.Contains(string(raw), leakedSecretForTest) {
		t.Fatalf("generic exposure create stored plaintext: %s", raw)
	}
}

func TestCredentialsReveal_OnlyOwnerAndAdminByDefault(t *testing.T) {
	has := func(role tenant.Role) bool {
		for _, p := range permission.RolePermissions[role] {
			if p == permission.CredentialsReveal {
				return true
			}
		}
		return false
	}
	if !has(tenant.RoleOwner) || !has(tenant.RoleAdmin) {
		t.Error("owner and admin must hold findings:credentials:reveal")
	}
	if has(tenant.RoleMember) || has(tenant.RoleViewer) {
		t.Error("member and viewer must not hold findings:credentials:reveal")
	}
}
