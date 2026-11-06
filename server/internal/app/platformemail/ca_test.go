package platformemail

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testCAPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// The CA bundle is write-only (reads say set + fingerprint), reaches the SMTP
// sender as its only roots, and the audit row carries the fingerprint, not the bundle.
func TestUpdate_CABundleWriteOnlyAndUsed(t *testing.T) {
	svc, _, audit := newTestService(t)
	ctx := context.Background()
	actor := superAdmin(t)
	ca := testCAPEM(t, "Corp mail CA")

	in := validInput(nil)
	in.CAPEM = &ca
	got, err := svc.Update(ctx, actor, in, 0, "", "")
	if err != nil || !got.CASet || len(got.CAFingerprint) != 64 {
		t.Fatalf("Update: %+v %v", got, err)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "BEGIN CERTIFICATE") {
		t.Fatal("the settings view returns the bundle")
	}
	for _, e := range audit.entries {
		b, _ := json.Marshal(e)
		if strings.Contains(string(b), "BEGIN CERTIFICATE") || !strings.Contains(string(b), got.CAFingerprint) {
			t.Fatalf("audit must hold the fingerprint and not the bundle: %s", b)
		}
	}
	cfg, ok := svc.senderConfig(ctx)
	if !ok || cfg.RootCAs == nil {
		t.Fatalf("the sender must verify against the bundle: %+v %v", cfg, ok)
	}

	// nil keeps it; "" removes it and the system roots apply again.
	if got, err = svc.Update(ctx, actor, validInput(nil), 1, "", ""); err != nil || !got.CASet {
		t.Fatalf("keep: %+v %v", got, err)
	}
	if got, err = svc.Update(ctx, actor, func() Input { i := validInput(nil); i.CAPEM = strp(""); return i }(), 2, "", ""); err != nil || got.CASet || got.CAFingerprint != "" {
		t.Fatalf("remove: %+v %v", got, err)
	}
	if cfg, _ := svc.senderConfig(ctx); cfg.RootCAs != nil {
		t.Fatal("a removed bundle must not stay in force")
	}
}

func TestUpdate_CABundleRefusesKeysAndJunk(t *testing.T) {
	svc, repo, _ := newTestService(t)
	for name, bad := range map[string]string{
		"private key": testCAPEM(t, "x") + "\n-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n",
		"text":        "not a certificate",
	} {
		in := validInput(nil)
		in.CAPEM = &bad
		if _, err := svc.Update(context.Background(), superAdmin(t), in, 0, "", ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		} else if err.Error() != errCAInvalid.Error() {
			t.Errorf("%s: a person reads %q, want the fixed sentence", name, err)
		}
		if len(repo.rows) != 0 {
			t.Fatalf("%s: a refused bundle was stored", name)
		}
	}
}

// A new or different trust root for the relay is a relay change: a second super admin approves it.
func TestApprovalNeeded_CAChange(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	ca := testCAPEM(t, "Corp mail CA")
	in := validInput(nil)
	in.CAPEM = &ca
	if _, err := svc.Update(ctx, superAdmin(t), in, 0, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, needed := svc.ApprovalNeeded(ctx, validInput(nil)); needed {
		t.Fatal("keeping the stored bundle needs no approval")
	}
	other := testCAPEM(t, "Another CA")
	for name, v := range map[string]*string{"replace": &other, "remove": strp("")} {
		i := validInput(nil)
		i.CAPEM = v
		if _, needed := svc.ApprovalNeeded(ctx, i); !needed {
			t.Errorf("%s: a changed trust root needs approval", name)
		}
	}
}

// An unparsable stored bundle turns e-mail off rather than falling back to the system roots.
func TestSenderConfig_FailsClosedOnBadCA(t *testing.T) {
	svc, repo, _ := newTestService(t)
	ctx := context.Background()
	if _, err := svc.Update(ctx, superAdmin(t), validInput(nil), 0, "", ""); err != nil {
		t.Fatal(err)
	}
	var st stored
	row := repo.rows[SettingKey]
	_ = json.Unmarshal(row.Value, &st)
	st.CAPEM = "garbage"
	row.Value, _ = json.Marshal(st)
	repo.rows[SettingKey] = row
	svc2 := NewService(repo, svc.encryptor, nil, nil)
	if _, ok := svc2.senderConfig(ctx); ok {
		t.Fatal("a bad stored CA bundle must turn e-mail off")
	}
}

// A headless install seeds the CA bundle with the rest; a key is refused.
func TestSeed_CABundle(t *testing.T) {
	svc, _, _ := newTestService(t)
	ca := testCAPEM(t, "Corp mail CA")
	in := validInput(nil)
	in.CAPEM = &ca
	if created, err := svc.Seed(context.Background(), in); err != nil || !created {
		t.Fatalf("seed: %v %v", created, err)
	}
	if got, _ := svc.Get(context.Background()); !got.CASet {
		t.Fatal("the seeded CA bundle is not stored")
	}
	svc2, _, _ := newTestService(t)
	bad := "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----"
	in.CAPEM = &bad
	if _, err := svc2.Seed(context.Background(), in); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a key must be refused: %v", err)
	}
}
