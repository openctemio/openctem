package threatalert

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/threatalert"
	"github.com/openctemio/openctem/server/pkg/logger"
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

// Messages and digests count hosts in the console's words: likely is its own
// number and no host count is called assets.
func TestMessagesCountHosts(t *testing.T) {
	a := &threatalert.Alert{VulnID: "CVE-2099-0001", ETS: 91, Confirmed: 3, Likely: 1, Possible: 2, InternetFacing: 2}
	d := threatalert.Digest{Immediate: 1, Top: []threatalert.DigestItem{
		{VulnID: "CVE-2099-0001", Title: "CVE-2099-0001", ETS: 91, Confirmed: 3, Likely: 1},
		{VulnID: "CVE-2099-0002", Title: "CVE-2099-0002", ETS: 60, Possible: 1, InternetFacing: 1},
	}}
	_, body := digestText(d, false)
	for _, want := range []string{"CVE-2099-0001 (score 91, 3 hosts confirmed, 1 likely)",
		"CVE-2099-0002 (score 60, 1 host possibly affected, 1 internet-facing)"} {
		if !strings.Contains(body, want) {
			t.Fatalf("digest body misses %q: %s", want, body)
		}
	}
	mail := (&Planner{webBase: "https://ctem.example.com"}).digestMail(shared.NewID(), d, false)
	if !strings.Contains(mail, "<li>CVE-2099-0001: score 91, 3 hosts confirmed, 1 likely</li>") {
		t.Fatalf("digest mail: %s", mail)
	}
	p := &Planner{}
	if got, want := p.affects(context.Background(), &policy{}, a), "3 hosts confirmed, 1 likely, 2 possibly affected, 2 internet-facing"; got != want {
		t.Fatalf("affects = %q, want %q", got, want)
	}
	title, baseline := digestText(threatalert.Digest{Exploited: 4}, true)
	for _, text := range []string{body, mail, title, baseline} {
		if strings.Contains(strings.ToLower(text), "asset") {
			t.Fatalf("a message names assets for a host count: %s", text)
		}
	}
}

// With names turned on a message names each host once, not each service.
func TestAffectsNamesHostsOnce(t *testing.T) {
	st := &fanOutStore{}
	p := NewPlanner(namedAssets{st}, nil, logger.NewNop())
	pol := &policy{}
	pol.settings.AssetNamesInMessages = true
	got := p.affects(context.Background(), pol, &threatalert.Alert{Confirmed: 1})
	if want := "1 host confirmed. Hosts: 192.0.2.20"; got != want {
		t.Fatalf("affects = %q, want %q", got, want)
	}
}

type namedAssets struct{ threatalert.PlannerStore }

func (namedAssets) AffectedAssets(context.Context, shared.ID, string) ([]threatalert.Asset, error) {
	return []threatalert.Asset{{AssetID: shared.NewID(), Name: "http://192.0.2.20", Kind: threatalert.MatchConfirmed},
		{AssetID: shared.NewID(), Name: "https://192.0.2.20", Kind: threatalert.MatchConfirmed}}, nil
}
