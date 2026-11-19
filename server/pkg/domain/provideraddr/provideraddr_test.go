package provideraddr

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/edgeaddr"
)

// testClassifier publishes documentation ranges as shared, so the tests do
// not depend on the real provider lists.
func testClassifier(t *testing.T) *edgeaddr.Classifier {
	t.Helper()
	c, err := edgeaddr.New(edgeaddr.Dataset{Version: "test-1", Ranges: []edgeaddr.RangeEntry{
		{Provider: "Example CDN", Class: edgeaddr.Edge, Prefixes: []string{"198.51.100.0/24", "2001:db8::/32"}},
		{Provider: "Example Front", Class: edgeaddr.CloudShared, Prefixes: []string{"203.0.113.0/25"}},
		{Provider: "Example Static", Class: edgeaddr.Dedicated, Prefixes: []string{"203.0.113.64/26"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCertificateCovers(t *testing.T) {
	cases := []struct {
		covers []string
		name   string
		want   bool
	}{
		{[]string{"app.example.com"}, "APP.example.com.", true},
		{[]string{"*.example.com"}, "app.example.com", true},
		{[]string{"*.example.com"}, "a.b.example.com", false},
		{[]string{"*.example.com"}, "example.com", false},
		{[]string{"other.example.com"}, "app.example.com", false},
		{nil, "app.example.com", false},
	}
	for _, c := range cases {
		if got := CertificateCovers(c.covers, c.name); got != c.want {
			t.Errorf("CertificateCovers(%v, %q) = %v, want %v", c.covers, c.name, got, c.want)
		}
	}
}

// An entry holds a provider address when it names exactly that address, or
// is a CIDR or range wholly inside a shared range; a wider entry (part of it
// may be the organization's) does not, and is not listed on the card.
func TestEntries_CoversAndCard(t *testing.T) {
	c := testClassifier(t)
	e := NewEntries([]ScopeEntry{
		{Type: "ip_address", Pattern: "198.51.100.10", Origin: "import"},
		{Type: "cidr", Pattern: "198.51.100.128/26", Origin: "review_rule"},
		{Type: "cidr", Pattern: "198.51.0.0/16", Origin: "manual"},
		{Type: "ip_range", Pattern: "203.0.113.1-203.0.113.9", Origin: "manual"},
		{Type: "ip_address", Pattern: "192.0.2.1", Origin: "manual"},
		{Type: "ip_address", Pattern: "::ffff:198.51.100.11", Origin: "import"},
	}, c)
	for addr, want := range map[string]bool{
		"198.51.100.10":  true,
		"198.51.100.11":  true,
		"198.51.100.130": true,
		"198.51.100.20":  false, // only the /16 covers it, and it is wider than the shared range
		"203.0.113.5":    true,
		"203.0.113.10":   false,
		"2001:db8::1":    false,
	} {
		if got := e.Covers(addr); got != want {
			t.Errorf("Covers(%s) = %v, want %v", addr, got, want)
		}
	}
	if e.Card[CountCardEntriesExact] != 2 || e.Card[CountCardEntriesRange] != 2 {
		t.Errorf("card = %v, want 2 exact and 2 ranges", e.Card)
	}
	if e.Card[CardEntryKey("range", "review_rule")] != 1 || e.Card[CardEntryKey("exact", "import")] != 2 {
		t.Errorf("card by origin = %v", e.Card)
	}
}

// Two edges from one name to two spellings of one address fold into one
// history row with the earliest first seen and the latest last seen.
func TestPlanBatch_FoldMergesSpellingsAndCounts(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	t1, t2 := t0.Add(24*time.Hour), t0.Add(72*time.Hour)
	in := BatchInput{
		Addresses: []Address{
			{ID: "a1", Name: "2001:DB8:0:0::5", Status: "active"},
		},
		Classes: map[string]edgeaddr.Result{"a1": {Class: edgeaddr.Edge, Provider: "Example CDN"}},
		Edges: []Edge{
			{ID: "e1", SourceID: "n1", TargetID: "a1", Type: "resolves_to", DiscoveryMethod: "automatic", CreatedAt: t1, LastVerified: &t2},
			{ID: "e2", SourceID: "n1", TargetID: "a1", Type: "resolves_to", DiscoveryMethod: "automatic", CreatedAt: t0},
		},
		Assets: map[string]Asset{"n1": {ID: "n1", Name: "mail.example.com", Type: "subdomain"}},
	}
	plan := PlanBatch(in, NewSimulation(), t2)
	if len(plan.Items) != 1 {
		t.Fatalf("items = %d", len(plan.Items))
	}
	it := plan.Items[0]
	if it.Address != "2001:db8::5" || it.Bucket != BucketPlain || it.Action != ActionArchive || it.NewStatus != "archived" {
		t.Fatalf("item = %+v", it)
	}
	if len(it.FoldedKeys) != 1 || !it.FoldedKeys[0].FirstSeen.Equal(t0) || !it.FoldedKeys[0].LastSeen.Equal(t2) {
		t.Fatalf("folded = %+v", it.FoldedKeys)
	}
	if plan.Counts[CountEdgesFolded] != 2 || plan.Counts[CountEdgesNotInHistory] != 1 || plan.Counts[CountArchived] != 1 {
		t.Fatalf("counts = %v", plan.Counts)
	}
	if it.NewAttribution == nil || it.NewAttribution.State != "dependency" || it.NewAttribution.Reason != Reason {
		t.Fatalf("attribution = %+v", it.NewAttribution)
	}
}

// Keep reasons: a person, an entry, a reference, a manual edge, services
// named by the address; a person's attribution is never replaced, and a
// discovered one becomes dependency.
func TestPlanBatch_KeepReasons(t *testing.T) {
	now := time.Now().UTC()
	decided := now
	in := BatchInput{
		Addresses: []Address{
			{ID: "person", Name: "198.51.100.1", Status: "active", Attribution: &Attribution{State: "confirmed", Confidence: 100, DecidedAt: &decided}},
			{ID: "entry", Name: "198.51.100.2", Status: "active", Attribution: &Attribution{State: "confirmed", Confidence: 100, Reason: "matches_scope_target"}},
			{ID: "ref", Name: "198.51.100.3", Status: "active", Tagged: true},
			{ID: "manual", Name: "198.51.100.4", Status: "active"},
			{ID: "svc", Name: "198.51.100.5", Status: "active", Attribution: &Attribution{State: "discovered", Confidence: 60}},
			{ID: "run", Name: "198.51.100.6", Status: "active"},
		},
		Classes:      map[string]edgeaddr.Result{},
		EntryCovered: map[string]bool{"entry": true},
		ActiveRun:    map[string]bool{"run": true},
		Edges: []Edge{
			{ID: "m1", SourceID: "n1", TargetID: "manual", Type: "depends_on", DiscoveryMethod: "manual", CreatedAt: now},
			{ID: "s1", SourceID: "svc", TargetID: "port", Type: "exposes", DiscoveryMethod: "automatic", CreatedAt: now},
			{ID: "r1", SourceID: "n1", TargetID: "person", Type: "resolves_to", DiscoveryMethod: "automatic", CreatedAt: now},
		},
		Assets: map[string]Asset{
			"n1":   {ID: "n1", Name: "mail.example.com", Type: "subdomain"},
			"port": {ID: "port", Name: "198.51.100.5:993:tcp", Type: "service"},
		},
	}
	for _, a := range in.Addresses {
		in.Classes[a.ID] = edgeaddr.Result{Class: edgeaddr.Edge, Provider: "Example CDN"}
	}
	plan := PlanBatch(in, NewSimulation(), now)
	got := map[string]Item{}
	for _, it := range plan.Items {
		got[it.AssetID] = it
	}
	if it := got["person"]; it.Bucket != BucketPerson || it.NewAttribution != nil || it.NewStatus != "" || len(it.Edges) != 1 {
		t.Errorf("person = %+v", it)
	}
	if _, ok := got["entry"]; ok {
		t.Errorf("entry-covered address with nothing to change was journaled")
	}
	if _, ok := got["ref"]; ok {
		t.Errorf("tagged address with nothing to change was journaled")
	}
	if it := got["svc"]; it.Bucket != BucketAddressServices || it.NewAttribution == nil || it.NewStatus != "" {
		t.Errorf("svc = %+v", it)
	}
	if it := got["run"]; it.Outcome != OutcomeSkippedActiveRun || it.Action != ActionSkip {
		t.Errorf("run = %+v", it)
	}
	for _, b := range []Bucket{BucketPerson, BucketEntry, BucketReference, BucketManualEdge, BucketAddressServices, BucketActiveRun} {
		if plan.Counts[AddressKey("Example CDN", b)] != 1 {
			t.Errorf("bucket %s count = %d (%v)", b, plan.Counts[AddressKey("Example CDN", b)], plan.Counts)
		}
	}
	if plan.Counts[CountArchived] != 0 || plan.Counts[CountKept] != 5 {
		t.Errorf("counts = %v", plan.Counts)
	}
}

// A service named by a host name moves to that name; a second batch that
// reaches the same service (a second provider address) adds nothing new and
// its findings are counted once.
func TestPlanBatch_RelinkAcrossBatches(t *testing.T) {
	now := time.Now().UTC()
	sim := NewSimulation()
	mk := func(addrID, addr string) BatchInput {
		return BatchInput{
			Addresses:   []Address{{ID: addrID, Name: addr, Status: "active"}},
			Classes:     map[string]edgeaddr.Result{addrID: {Class: edgeaddr.Edge, Provider: "Example CDN"}},
			Edges:       []Edge{{ID: "x" + addrID, SourceID: addrID, TargetID: "svc", Type: "exposes", DiscoveryMethod: "inferred", Confidence: "medium", ImpactWeight: 5, CreatedAt: now}},
			Assets:      map[string]Asset{"svc": {ID: "svc", Name: "https://app.example.com", Type: "service"}, "name": {ID: "name", Name: "app.example.com", Type: "subdomain"}},
			NamesByHost: map[string]string{"app.example.com": "name"},
			Findings:    map[string]map[string]int{"svc": {"critical": 1, "none": 3}},
		}
	}
	p1 := PlanBatch(mk("a1", "198.51.100.1"), sim, now)
	p2 := PlanBatch(mk("a2", "198.51.100.2"), sim, now)
	if len(p1.Items[0].AddedEdges) != 1 || len(p2.Items[0].AddedEdges) != 0 {
		t.Fatalf("added = %d, %d", len(p1.Items[0].AddedEdges), len(p2.Items[0].AddedEdges))
	}
	if p1.Items[0].Bucket != BucketPlainAfterRelink || p2.Items[0].Bucket != BucketPlainAfterRelink {
		t.Fatalf("buckets = %s, %s", p1.Items[0].Bucket, p2.Items[0].Bucket)
	}
	total := Counts{}
	total.Merge(p1.Counts)
	total.Merge(p2.Counts)
	if total[SeverityKey("critical")] != 1 || total[SeverityKey("none")] != 3 || total[CountServicesRelinked] != 2 {
		t.Fatalf("counts = %v", total)
	}
	e := p1.Items[0].AddedEdges[0]
	if e.SourceID != "name" || e.TargetID != "svc" || e.Type != "exposes" || e.DiscoveryMethod != "inferred" || *e.Description != RelinkDescription {
		t.Fatalf("added edge = %+v", e)
	}
}

func TestKeys_RoundTrip(t *testing.T) {
	p, b, ok := ParseAddressKey(AddressKey("Example: CDN", BucketPlain))
	if !ok || p != "Example: CDN" || b != BucketPlain {
		t.Fatalf("address key = %q %q %v", p, b, ok)
	}
	if s, ok := ParseSeverityKey(SeverityKey("high")); !ok || s != "high" {
		t.Fatal("severity key")
	}
	if k, o, ok := ParseCardEntryKey(CardEntryKey("exact", "import")); !ok || k != "exact" || o != "import" {
		t.Fatal("card key")
	}
}

func TestNewNotice(t *testing.T) {
	n := NewNotice(3, 2, 0, []string{"Example CDN"})
	if n.En == "" || n.Vi == "" || n.Addresses != 3 || n.Names != 2 {
		t.Fatalf("notice = %+v", n)
	}
	with := NewNotice(3, 2, 4, nil)
	if with.En == n.En {
		t.Fatal("entries are not mentioned")
	}
}
