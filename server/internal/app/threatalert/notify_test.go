package threatalert

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/threatalert"
)

func TestWhyNowJoinsWithCommasNotMiddleDots(t *testing.T) {
	epss := 0.97
	a := &threatalert.Alert{InKEV: true, KEVRansomware: true, EPSS: &epss, Severity: "critical"}
	got := whyNow(a)
	want := "in the CISA KEV catalog (known ransomware use), EPSS 0.97, severity critical"
	if got != want {
		t.Fatalf("whyNow = %q, want %q", got, want)
	}
	if strings.ContainsRune(got, '·') {
		t.Fatalf("whyNow carries a middle dot: %q", got)
	}
}

func TestWhyNowSingleReasonAndFallback(t *testing.T) {
	if got := whyNow(&threatalert.Alert{Severity: "high"}); got != "severity high" {
		t.Fatalf("got %q", got)
	}
	if got := whyNow(&threatalert.Alert{}); got != "newly published" {
		t.Fatalf("got %q", got)
	}
}

// The digest e-mail link names the organization, so a member of several
// organizations who opens it while another one is selected lands on its list.
func TestDigestMailLinkNamesOrganization(t *testing.T) {
	tenant := shared.NewID()
	p := &Planner{webBase: "https://ctem.example.com/"}
	body := p.digestMail(tenant, threatalert.Digest{Immediate: 1}, false)
	want := `href="https://ctem.example.com/emerging-threats?org=` + tenant.String() + `"`
	if !strings.Contains(body, want) {
		t.Fatalf("digest mail link: want %s in %s", want, body)
	}
}
