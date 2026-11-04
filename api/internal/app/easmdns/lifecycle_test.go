package easmdns

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/dnsprobe"
	"github.com/openctemio/openctem/api/pkg/dnsprobe/dnstest"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func eventsOf(m *memStore, typ exposuredom.EventType) []*exposuredom.ExposureEvent {
	var out []*exposuredom.ExposureEvent
	for _, e := range m.exposure {
		if e.EventType() == typ {
			out = append(out, e)
		}
	}
	return out
}

// A dangling target that starts to exist outside the organization is what a
// takeover looks like: the dangling_cname stays open, a suspected takeover is
// raised, the tag stays; nothing is auto-resolved.
func TestLifecycle_TargetAppearsElsewhereRaisesSuspectedTakeover(t *testing.T) {
	tenant := shared.NewID()
	shop := Target{AssetID: shared.NewID(), Name: "shop.acme.example.com"}
	store := newMemStore(shop)
	svc, srv := serviceWith(t, map[string]dnstest.Entry{
		"shop.acme.example.com": {CNAME: "acme-shop.azurewebsites.net"},
		"azurewebsites.net":     {NS: []string{"ns1.azure.example"}},
	}, store)
	ctx := context.Background()
	if res, err := svc.MonitorTenant(ctx, tenant); err != nil || res.Found != 1 || !store.tags[shop.AssetID] {
		t.Fatalf("first run: %+v %v tag=%v", res, err, store.tags[shop.AssetID])
	}
	dangling := eventsOf(store, exposuredom.EventTypeDanglingCNAME)[0]
	if dangling.Details()["response_class"] != ClassNXDomainTarget {
		t.Fatalf("details = %v", dangling.Details())
	}

	// Someone created acme-shop.azurewebsites.net: it now resolves to a
	// provider address that is not the organization's.
	srv.Set(map[string]dnstest.Entry{
		"shop.acme.example.com":       {CNAME: "acme-shop.azurewebsites.net"},
		"acme-shop.azurewebsites.net": {A: []string{"203.0.113.50"}},
	})
	res, err := svc.MonitorTenant(ctx, tenant)
	if err != nil || res.Resolved != 0 {
		t.Fatalf("second run resolved something: %+v %v", res, err)
	}
	if store.state[dangling.Fingerprint()] != "active" || !store.tags[shop.AssetID] {
		t.Fatalf("dangling state=%s tag=%v", store.state[dangling.Fingerprint()], store.tags[shop.AssetID])
	}
	tk := eventsOf(store, exposuredom.EventTypeSubdomainTakeover)
	if len(tk) != 1 || tk[0].Severity() != exposuredom.SeverityHigh || tk[0].Details()["check"] != "target_changed" ||
		tk[0].Details()["confirmation"] != "suspected" || tk[0].Details()["previous_target"] != "acme-shop.azurewebsites.net" {
		t.Fatalf("takeover = %+v", tk)
	}

	// The organization points the name at its own server: everything resolves.
	store.addrs["198.51.100.7"] = AddressFact{Confirmed: true}
	srv.Set(map[string]dnstest.Entry{"shop.acme.example.com": {A: []string{"198.51.100.7"}}})
	if res, _ := svc.MonitorTenant(ctx, tenant); res.Resolved != 2 || store.tags[shop.AssetID] {
		t.Fatalf("owned run: %+v tag=%v", res, store.tags[shop.AssetID])
	}
}

// Ownership: the same registrable domain or a confirmed root is the
// organization's; an address is only when it is a confirmed asset outside
// provider space; an address another source merely discovered is not.
func TestLifecycle_Ownership(t *testing.T) {
	tenant := shared.NewID()
	ctx := context.Background()
	svc := NewService(nil, newMemStore(), nil, logger.NewNop())
	store := svc.store.(*memStore)
	store.rootOwned["acme-cdn.com"] = true
	store.addrs["198.51.100.7"] = AddressFact{Confirmed: true}
	store.addrs["198.51.100.8"] = AddressFact{Confirmed: false}
	store.addrs["104.16.0.1"] = AddressFact{Confirmed: true, ASNOrg: "Cloudflare, Inc."}
	for name, c := range map[string]struct {
		d    Dangling
		want bool
	}{
		"same apex":         {Dangling{Outcome: OutcomeOK, Target: "www.acme.example.com", Chain: []string{"www.acme.example.com"}}, true},
		"confirmed root":    {Dangling{Outcome: OutcomeOK, Target: "edge.acme-cdn.com", Chain: []string{"edge.acme-cdn.com"}}, true},
		"third party":       {Dangling{Outcome: OutcomeOK, Target: "dns.ladipage.com", Chain: []string{"dns.ladipage.com"}}, false},
		"own address":       {Dangling{Outcome: OutcomeOK, Addresses: []string{"198.51.100.7"}}, true},
		"unconfirmed":       {Dangling{Outcome: OutcomeOK, Addresses: []string{"198.51.100.7", "198.51.100.8"}}, false},
		"unknown address":   {Dangling{Outcome: OutcomeOK, Addresses: []string{"192.0.2.200"}}, false},
		"provider space":    {Dangling{Outcome: OutcomeOK, Addresses: []string{"104.16.0.1"}}, false},
		"record is removed": {Dangling{Outcome: OutcomeOK}, true},
	} {
		got, err := svc.ownedResolution(ctx, tenant, "shop.acme.example.com", c.d)
		if err != nil || got != c.want {
			t.Errorf("%s: owned=%v err=%v, want %v", name, got, err, c.want)
		}
	}
}

// A name hosted by a listed provider whose target resolves: nothing until the
// tenant's scans record certificate trouble on the name, then dangling_cname
// (provider_refuses, high for a provider anyone can claim on). It resolves
// once the provider serves a valid certificate for the name again.
func TestLifecycle_ProviderRefuses(t *testing.T) {
	tenant := shared.NewID()
	name := Target{AssetID: shared.NewID(), Name: "ebook.acme.example.com"}
	store := newMemStore(name)
	svc, _ := serviceWith(t, map[string]dnstest.Entry{
		"ebook.acme.example.com": {CNAME: "dns.ladipage.com"},
		"dns.ladipage.com":       {A: []string{"203.0.113.114"}},
	}, store)
	ctx := context.Background()
	if res, _ := svc.MonitorTenant(ctx, tenant); res.Found != 0 || store.tags[name.AssetID] {
		t.Fatalf("a served provider name was flagged: %+v", res)
	}

	store.trouble[name.Name] = []CertTrouble{{Kind: "expired", NotAfter: "2025-11-08T00:00:00Z", Issuer: "R10"}}
	if res, _ := svc.MonitorTenant(ctx, tenant); res.Found != 1 || !store.tags[name.AssetID] {
		t.Fatalf("refusing provider not flagged: %+v", res)
	}
	ev := eventsOf(store, exposuredom.EventTypeDanglingCNAME)[0]
	d := ev.Details()
	if ev.Severity() != exposuredom.SeverityHigh || d["response_class"] != ClassProviderRefuses || d["provider"] != "LadiPage" ||
		d["provider_claimable"] != "yes" || d["confirmation"] != "pending" || d["tls_state"] == nil || d["check"] != "provider_answer" {
		t.Fatalf("event = %s %v", ev.Severity(), d)
	}

	// Still refusing: kept, not duplicated, not resolved.
	if res, _ := svc.MonitorTenant(ctx, tenant); res.Resolved != 0 || len(store.exposure) != 1 {
		t.Fatalf("re-run: %+v rows=%d", res, len(store.exposure))
	}

	// The provider serves the name again (certificate exposures resolved).
	delete(store.trouble, name.Name)
	if res, _ := svc.MonitorTenant(ctx, tenant); res.Resolved != 1 || store.tags[name.AssetID] {
		t.Fatalf("served again: %+v tag=%v", res, store.tags[name.AssetID])
	}
}

// A provider not in the lists never yields provider_refuses: certificate
// trouble alone is the host-certificate exposure's job.
func TestLifecycle_UnlistedProviderIsNotDangling(t *testing.T) {
	tenant := shared.NewID()
	name := Target{AssetID: shared.NewID(), Name: "app.acme.example.com"}
	store := newMemStore(name)
	store.trouble[name.Name] = []CertTrouble{{Kind: "expired"}}
	svc, _ := serviceWith(t, map[string]dnstest.Entry{
		"app.acme.example.com":         {CNAME: "lb.unlisted-host.example.net"},
		"lb.unlisted-host.example.net": {A: []string{"203.0.113.9"}},
	}, store)
	if res, _ := svc.MonitorTenant(context.Background(), tenant); res.Found != 0 {
		t.Fatalf("flagged: %+v", res)
	}
}

// A takeover match on a provider-hosted name with no open dangling_cname
// raises the dangling_cname (provider_unclaimed_page, confirmed) and the
// takeover; a match whose chain stays in the organization, or ends at an
// unlisted host, raises nothing.
func TestConfirmTakeovers_ProviderHostedName(t *testing.T) {
	tenant := shared.NewID()
	hosted, inOrg, unlisted := shared.NewID(), shared.NewID(), shared.NewID()
	srv, err := dnstest.Start(map[string]dnstest.Entry{
		"promo.acme.example.com":    {CNAME: "dns.ladipage.com"},
		"dns.ladipage.com":          {A: []string{"203.0.113.114"}},
		"www.acme.example.com":      {CNAME: "lb.acme.example.com"},
		"lb.acme.example.com":       {A: []string{"198.51.100.1"}},
		"x.acme.example.com":        {CNAME: "edge.unlisted.example.net"},
		"edge.unlisted.example.net": {A: []string{"203.0.113.1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	q, _ := dnsprobe.New(dnsprobe.Config{Server: srv.Addr, QPS: 1000})
	store := &fakeTakeoverStore{names: map[shared.ID]string{
		hosted: "promo.acme.example.com", inOrg: "www.acme.example.com", unlisted: "x.acme.example.com",
	}}
	up := &fakeUpserter{}
	c := NewTakeoverConfirmer(store, up, logger.NewNop())
	c.SetResolver(q)
	n, err := c.ConfirmTakeovers(context.Background(), tenant, []TakeoverSighting{
		{AssetID: hosted, TemplateID: "ladipage-takeover", SensorID: shared.NewID()},
		{AssetID: inOrg, TemplateID: "ladipage-takeover", SensorID: shared.NewID()},
		{AssetID: unlisted, TemplateID: "ladipage-takeover", SensorID: shared.NewID()},
	})
	if err != nil || n != 1 || len(up.events) != 2 {
		t.Fatalf("n=%d events=%d err=%v", n, len(up.events), err)
	}
	for _, ev := range up.events {
		if *ev.AssetID() != hosted || ev.TenantID() != tenant || ev.Severity() != exposuredom.SeverityHigh {
			t.Fatalf("event on the wrong asset or tenant: %+v", ev)
		}
		if ev.EventType() == exposuredom.EventTypeDanglingCNAME {
			d := ev.Details()
			if d["response_class"] != ClassProviderPage || d["confirmation"] != "confirmed" || d["provider"] != "LadiPage" {
				t.Fatalf("dangling details = %v", d)
			}
		}
	}
	// Without a resolver, the old rule stands: no open dangling, no takeover.
	up2 := &fakeUpserter{}
	if n, _ := NewTakeoverConfirmer(store, up2, logger.NewNop()).ConfirmTakeovers(context.Background(), tenant,
		[]TakeoverSighting{{AssetID: hosted, TemplateID: "ladipage-takeover"}}); n != 0 || len(up2.events) != 0 {
		t.Fatalf("raised without a resolver: %d", n)
	}
}

func TestOwnProviderList_LadiPage(t *testing.T) {
	p, ok := providerFor("dns.ladipage.com")
	if !ok || p.Service != "LadiPage" || !p.Hosted || !p.Takeoverable() {
		t.Fatalf("provider = %+v %v", p, ok)
	}
	// The third-party list is still read.
	if p, ok := providerFor("gone.azurewebsites.net"); !ok || p.Hosted {
		t.Fatalf("azure = %+v %v", p, ok)
	}
}
