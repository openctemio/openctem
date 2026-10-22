package domainverify

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type capturedLoss struct {
	tenants []shared.ID
	domains []string
}

func (c *capturedLoss) SSODomainVerificationLost(_ context.Context, tenantID shared.ID, domain string) {
	c.tenants = append(c.tenants, tenantID)
	c.domains = append(c.domains, domain)
}

// T24: a verified SSO domain whose TXT record vanished tells the listener
// (which alerts the owners) once, on the transition, for its own tenant only.
func TestReverifyDue_LapsedSSODomainAlertsOnce(t *testing.T) {
	repo := newMemRepo()
	res := &mockResolver{records: map[string][]string{}}
	svc := NewService(repo, res, nil)
	loss := &capturedLoss{}
	svc.SetDomainLossListener(loss)

	lapsed, healthy := shared.NewID(), shared.NewID()
	id, token := mustAdd(t, svc, lapsed, "corp.example.com")
	hid, htoken := mustAdd(t, svc, healthy, "other.example.com")
	res.records["_openctem-verify.corp.example.com"] = []string{"openctem-domain-verification=" + token}
	res.records["_openctem-verify.other.example.com"] = []string{"openctem-domain-verification=" + htoken}
	if _, err := svc.VerifyByID(context.Background(), lapsed, id); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyByID(context.Background(), healthy, hid); err != nil {
		t.Fatal(err)
	}

	res.records["_openctem-verify.corp.example.com"] = nil
	if _, err := svc.ReverifyDue(context.Background(), 0, 100); err != nil {
		t.Fatal(err)
	}
	if len(loss.tenants) != 1 || loss.tenants[0] != lapsed || loss.domains[0] != "corp.example.com" {
		t.Fatalf("expected one alert for the lapsed tenant's domain, got %v %v", loss.tenants, loss.domains)
	}

	// Still failing on the next sweep: no repeat.
	if _, err := svc.ReverifyDue(context.Background(), 0, 100); err != nil {
		t.Fatal(err)
	}
	if len(loss.tenants) != 1 {
		t.Fatalf("a domain that stays failed must not alert again, got %d alerts", len(loss.tenants))
	}
}

func TestHasVerifiedSSODomain(t *testing.T) {
	repo := newMemRepo()
	res := &mockResolver{records: map[string][]string{}}
	svc := NewService(repo, res, nil)
	tid, other := shared.NewID(), shared.NewID()
	id, token := mustAdd(t, svc, tid, "corp.example.com")
	if ok, err := svc.HasVerifiedSSODomain(context.Background(), tid); err != nil || ok {
		t.Fatalf("a pending domain is not verified: %v %v", ok, err)
	}
	res.records["_openctem-verify.corp.example.com"] = []string{"openctem-domain-verification=" + token}
	if _, err := svc.VerifyByID(context.Background(), tid, id); err != nil {
		t.Fatal(err)
	}
	if ok, _ := svc.HasVerifiedSSODomain(context.Background(), tid); !ok {
		t.Fatal("a verified SSO domain must count")
	}
	if ok, _ := svc.HasVerifiedSSODomain(context.Background(), other); ok {
		t.Fatal("another tenant's verified domain must not count")
	}
}
