package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sort"
	"strings"
	"testing"
	"time"

	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	samldom "github.com/openctemio/openctem/api/pkg/domain/samlprovider"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ssochange"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func certPEMValidUntil(t *testing.T, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "idp"},
		NotBefore: notAfter.Add(-400 * 24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

type fakeCertStore struct {
	recs []samldom.CertificateRecord
}

// ListEnabledCertificates pages by tenant id like the Postgres store.
func (f *fakeCertStore) ListEnabledCertificates(_ context.Context, after shared.ID, limit int) ([]samldom.CertificateRecord, error) {
	sorted := append([]samldom.CertificateRecord(nil), f.recs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].TenantID.String() < sorted[j].TenantID.String() })
	var out []samldom.CertificateRecord
	for _, r := range sorted {
		if (after.IsZero() || r.TenantID.String() > after.String()) && len(out) < limit {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeCertStore) SetCertificateNotice(_ context.Context, tenantID shared.ID, days int) error {
	for i := range f.recs {
		if f.recs[i].TenantID == tenantID {
			d := days
			f.recs[i].NoticeDays = &d
		}
	}
	return nil
}

type fakeCertOwners map[shared.ID][]ssochange.OwnerContact

func (f fakeCertOwners) ListActiveOwners(_ context.Context, tenantID shared.ID) ([]ssochange.OwnerContact, error) {
	return f[tenantID], nil
}

type capturedInApp struct {
	got []notificationdom.NotificationParams
}

func (c *capturedInApp) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	c.got = append(c.got, p)
	return nil
}

type capturedCertMail struct{ to []string }

func (c *capturedCertMail) NotifySAMLCertificateExpiry(_ context.Context, email, _, _, _ string) {
	c.to = append(c.to, email)
}

func TestSAMLCertNoticeFor(t *testing.T) {
	now := time.Now()
	day := 24 * time.Hour
	cases := []struct {
		in   time.Duration
		want int
	}{
		{60 * day, -1}, {31 * day, -1}, {30 * day, 30}, {20 * day, 30}, {7 * day, 7}, {3 * day, 7},
		{day, 1}, {time.Hour, 1}, {0, 0}, {-5 * day, 0},
	}
	for _, c := range cases {
		if got := samlCertNoticeFor(now.Add(c.in), now); got != c.want {
			t.Errorf("expires in %v: got %d, want %d", c.in, got, c.want)
		}
	}
}

// Owners are alerted once per level, only the owners of the organization whose
// certificate expires, and again when it reaches a tighter level.
func TestSAMLCertExpirySweep(t *testing.T) {
	now := time.Now()
	expiring, healthy := shared.NewID(), shared.NewID()
	store := &fakeCertStore{recs: []samldom.CertificateRecord{
		{TenantID: expiring, Certificate: certPEMValidUntil(t, now.Add(20*24*time.Hour))},
		{TenantID: healthy, Certificate: certPEMValidUntil(t, now.Add(200*24*time.Hour))},
	}}
	ownerA, ownerB := shared.NewID(), shared.NewID()
	owners := fakeCertOwners{
		expiring: {{UserID: ownerA, Email: "owner@acme.example.com"}},
		healthy:  {{UserID: ownerB, Email: "owner@other.example.com"}},
	}
	inApp, mail := &capturedInApp{}, &capturedCertMail{}
	svc := NewSAMLService(nil, nil, nil, logger.NewNop())
	svc.SetCertExpiryAlerts(store, owners, inApp)
	svc.SetCertExpiryMailer(mail)

	n, err := svc.SweepCertificateExpiry(context.Background(), now)
	if err != nil || n != 1 {
		t.Fatalf("first sweep: n=%d err=%v, want one organization alerted", n, err)
	}
	if len(inApp.got) != 1 || *inApp.got[0].AudienceID != ownerA || inApp.got[0].TenantID != expiring {
		t.Fatalf("alert must reach only the expiring organization's owner, got %+v", inApp.got)
	}
	if len(mail.to) != 1 || mail.to[0] != "owner@acme.example.com" {
		t.Fatalf("owner email: %v", mail.to)
	}
	if !strings.Contains(inApp.got[0].Body, now.Add(20*24*time.Hour).UTC().Format("2006-01-02")) {
		t.Fatalf("alert must name the expiry date: %q", inApp.got[0].Body)
	}

	if n, _ := svc.SweepCertificateExpiry(context.Background(), now.Add(time.Hour)); n != 0 {
		t.Fatalf("the same level must not alert twice, got %d", n)
	}
	if n, _ := svc.SweepCertificateExpiry(context.Background(), now.Add(14*24*time.Hour)); n != 1 {
		t.Fatalf("reaching the 7-day level must alert again, got %d", n)
	}
	if n, _ := svc.SweepCertificateExpiry(context.Background(), now.Add(21*24*time.Hour)); n != 1 {
		t.Fatalf("expiry must alert, got %d", n)
	}
	last := inApp.got[len(inApp.got)-1]
	if !strings.Contains(last.Title, "expired") {
		t.Fatalf("expired alert title: %q", last.Title)
	}
}

// Every enabled organization is swept, not only the first page: an
// organization past the first page must still be alerted.
func TestSAMLCertExpirySweepPagesThroughAllOrganizations(t *testing.T) {
	prev := samlCertSweepPage
	samlCertSweepPage = 2
	t.Cleanup(func() { samlCertSweepPage = prev })

	now := time.Now()
	store := &fakeCertStore{}
	owners := fakeCertOwners{}
	for i := 0; i < 5; i++ {
		tid := shared.NewID()
		store.recs = append(store.recs, samldom.CertificateRecord{TenantID: tid,
			Certificate: certPEMValidUntil(t, now.Add(3*24*time.Hour))})
		owners[tid] = []ssochange.OwnerContact{{UserID: shared.NewID()}}
	}
	inApp := &capturedInApp{}
	svc := NewSAMLService(nil, nil, nil, logger.NewNop())
	svc.SetCertExpiryAlerts(store, owners, inApp)

	n, err := svc.SweepCertificateExpiry(context.Background(), now)
	if err != nil || n != 5 {
		t.Fatalf("sweep: n=%d err=%v, want all 5 organizations alerted", n, err)
	}
	if len(inApp.got) != 5 {
		t.Fatalf("alerts: got %d, want 5", len(inApp.got))
	}
}

// Without the alerts wired the sweep is a no-op, never a panic.
func TestSAMLCertExpirySweepUnwired(t *testing.T) {
	svc := NewSAMLService(nil, nil, nil, logger.NewNop())
	if n, err := svc.SweepCertificateExpiry(context.Background(), time.Now()); n != 0 || err != nil {
		t.Fatalf("unwired sweep: %d %v", n, err)
	}
}

// An expired IdP certificate is refused at save: it would fail every
// signature check.
func TestSAMLConfigRefusesExpiredCertificate(t *testing.T) {
	svc, _ := newSAMLForTest()
	_, err := svc.UpsertConfig(context.Background(), shared.NewID(), SAMLConfigInput{
		IDPEntityID: "https://idp.example.com", IDPSSOURL: "https://idp.example.com/sso",
		IDPCertificate: certPEMValidUntil(t, time.Now().Add(-time.Hour)),
	})
	if !errors.Is(err, ErrSAMLCertExpired) {
		t.Fatalf("expired certificate: got %v", err)
	}
}

func TestCertificateNotAfter(t *testing.T) {
	at := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	if got := CertificateNotAfter(certPEMValidUntil(t, at)); !got.Equal(at.UTC()) {
		t.Fatalf("got %v, want %v", got, at)
	}
	if !CertificateNotAfter("garbage").IsZero() {
		t.Fatal("an unparseable certificate has no expiry")
	}
}
