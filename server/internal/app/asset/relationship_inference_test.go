package asset

import (
	"testing"

	assetdom "github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// edgeKey identifies an inferred edge for assertion lookups.
type edgeKey struct {
	src, tgt string
	relType  assetdom.RelationshipType
}

func autoEdgeSet(res InferenceResult) map[edgeKey]InferredEdge {
	m := make(map[edgeKey]InferredEdge, len(res.AutoEdges))
	for _, e := range res.AutoEdges {
		m[edgeKey{e.SourceID.String(), e.TargetID.String(), e.Type}] = e
	}
	return m
}

func suggestionSet(res InferenceResult) map[edgeKey]InferredEdge {
	m := make(map[edgeKey]InferredEdge, len(res.Suggestions))
	for _, e := range res.Suggestions {
		m[edgeKey{e.SourceID.String(), e.TargetID.String(), e.Type}] = e
	}
	return m
}

// TestInferGraphEdges_ExposesFromOpenPort proves the core Exposes inference:
// an ip_address container that a Naabu open_port names via properties.host
// gets a directed `Exposes` edge (container → service), high confidence.
func TestInferGraphEdges_ExposesFromOpenPort(t *testing.T) {
	ipID := shared.NewID()
	portID := shared.NewID()

	assets := []GraphAsset{
		{ID: ipID, Type: assetdom.AssetTypeIPAddress, Name: "203.0.113.10"},
		{
			ID:      portID,
			Type:    assetdom.AssetTypeService,
			SubType: "open_port",
			Name:    "203.0.113.10:22/tcp",
			Props:   map[string]any{"host": "203.0.113.10", "port": 22},
		},
	}

	res := InferGraphEdges(assets)
	auto := autoEdgeSet(res)

	edge, ok := auto[edgeKey{ipID.String(), portID.String(), assetdom.RelTypeExposes}]
	if !ok {
		t.Fatalf("expected Exposes edge ip_address→open_port, got auto=%+v", res.AutoEdges)
	}
	if edge.Confidence != assetdom.ConfidenceHigh {
		t.Errorf("expected high confidence, got %s", edge.Confidence)
	}
	if len(res.Suggestions) != 0 {
		t.Errorf("expected no suggestions, got %+v", res.Suggestions)
	}
	// Direction must be container→service, never the reverse.
	if _, reversed := auto[edgeKey{portID.String(), ipID.String(), assetdom.RelTypeExposes}]; reversed {
		t.Error("edge direction reversed: service→container is wrong")
	}
}

// TestInferGraphEdges_ExposesFromHTTPService covers HTTPX live-host services
// that carry their host in properties.ip (and name themselves by hostname):
// the matching host asset exposes them.
func TestInferGraphEdges_ExposesFromHTTPService(t *testing.T) {
	hostID := shared.NewID()
	svcID := shared.NewID()

	assets := []GraphAsset{
		{
			ID:    hostID,
			Type:  assetdom.AssetTypeHost,
			Name:  "web01",
			Props: map[string]any{"ip_addresses": []string{"10.0.0.5"}, "hostname": "web01"},
		},
		{
			ID:      svcID,
			Type:    assetdom.AssetTypeHTTPService,
			SubType: "http",
			Name:    "shop.example.com",
			Props:   map[string]any{"ip": "10.0.0.5", "web_server": "nginx"},
		},
	}

	res := InferGraphEdges(assets)
	auto := autoEdgeSet(res)
	if _, ok := auto[edgeKey{hostID.String(), svcID.String(), assetdom.RelTypeExposes}]; !ok {
		t.Fatalf("expected Exposes host→http_service via shared IP, got %+v", res.AutoEdges)
	}
}

// TestInferGraphEdges_RunsOnApplication proves the RunsOn inference:
// an application co-located with a host by shared IP runs_on it (app→host).
func TestInferGraphEdges_RunsOnApplication(t *testing.T) {
	hostID := shared.NewID()
	appID := shared.NewID()

	assets := []GraphAsset{
		{ID: hostID, Type: assetdom.AssetTypeIPAddress, Name: "198.51.100.7"},
		{
			ID:    appID,
			Type:  assetdom.AssetTypeApplication,
			Name:  "payments-api",
			Props: map[string]any{"ip": "198.51.100.7"},
		},
	}

	res := InferGraphEdges(assets)
	auto := autoEdgeSet(res)
	edge, ok := auto[edgeKey{appID.String(), hostID.String(), assetdom.RelTypeRunsOn}]
	if !ok {
		t.Fatalf("expected RunsOn application→host, got %+v", res.AutoEdges)
	}
	if edge.Confidence != assetdom.ConfidenceHigh {
		t.Errorf("expected high confidence, got %s", edge.Confidence)
	}
}

// TestInferGraphEdges_AmbiguousHostIsSuggestionNotAuto proves the correctness
// gate: when a service's host key matches MULTIPLE candidate containers we do
// not guess — no auto edge is created; both candidates are emitted as
// suggestions for human review.
func TestInferGraphEdges_AmbiguousHostIsSuggestionNotAuto(t *testing.T) {
	ipA := shared.NewID()
	ipB := shared.NewID()
	portID := shared.NewID()

	// Two distinct containers share the same address (e.g. a stale duplicate
	// or NAT) — the port's host key is therefore ambiguous.
	assets := []GraphAsset{
		{ID: ipA, Type: assetdom.AssetTypeIPAddress, Name: "192.0.2.50"},
		{ID: ipB, Type: assetdom.AssetTypeHost, Name: "dup-host",
			Props: map[string]any{"ip_addresses": []string{"192.0.2.50"}}},
		{
			ID:      portID,
			Type:    assetdom.AssetTypeService,
			SubType: "open_port",
			Name:    "192.0.2.50:443/tcp",
			Props:   map[string]any{"host": "192.0.2.50"},
		},
	}

	res := InferGraphEdges(assets)
	if len(res.AutoEdges) != 0 {
		t.Fatalf("ambiguous match must not auto-apply, got %+v", res.AutoEdges)
	}
	sugg := suggestionSet(res)
	if _, ok := sugg[edgeKey{ipA.String(), portID.String(), assetdom.RelTypeExposes}]; !ok {
		t.Error("expected suggestion for candidate container A")
	}
	if _, ok := sugg[edgeKey{ipB.String(), portID.String(), assetdom.RelTypeExposes}]; !ok {
		t.Error("expected suggestion for candidate container B")
	}
	for _, e := range res.Suggestions {
		if e.Confidence != assetdom.ConfidenceLow {
			t.Errorf("suggestions should be low confidence, got %s", e.Confidence)
		}
	}
}

// TestInferGraphEdges_NoDuplicateEdges proves idempotency at the inference
// level: multiple host keys that all resolve to the same container yield a
// single edge (the caller's ON CONFLICT DO NOTHING is the second guard).
func TestInferGraphEdges_NoDuplicateEdges(t *testing.T) {
	ipID := shared.NewID()
	svcID := shared.NewID()

	assets := []GraphAsset{
		{ID: ipID, Type: assetdom.AssetTypeIPAddress, Name: "203.0.113.9"},
		{
			ID:    svcID,
			Type:  assetdom.AssetTypeService,
			Name:  "203.0.113.9", // clean host-key Name AND host/ip props all point to same container
			Props: map[string]any{"host": "203.0.113.9", "ip": "203.0.113.9"},
		},
	}

	res := InferGraphEdges(assets)
	if len(res.AutoEdges) != 1 {
		t.Fatalf("expected exactly 1 edge (deduped across keys), got %d: %+v", len(res.AutoEdges), res.AutoEdges)
	}
}

// TestInferGraphEdges_NoContainerNoEdge proves conservatism: a service whose
// host has no matching container asset produces nothing (no fabricated node,
// no edge).
func TestInferGraphEdges_NoContainerNoEdge(t *testing.T) {
	assets := []GraphAsset{
		{
			ID:      shared.NewID(),
			Type:    assetdom.AssetTypeService,
			SubType: "open_port",
			Name:    "10.10.10.10:22/tcp",
			Props:   map[string]any{"host": "10.10.10.10"},
		},
	}
	res := InferGraphEdges(assets)
	if len(res.AutoEdges) != 0 || len(res.Suggestions) != 0 {
		t.Fatalf("expected no edges without a container, got auto=%+v sugg=%+v", res.AutoEdges, res.Suggestions)
	}
}

// TestInferGraphEdges_DiscoveredURLExcluded proves crawled URLs (sub_type
// discovered_url) are not treated as listening services.
func TestInferGraphEdges_DiscoveredURLExcluded(t *testing.T) {
	ipID := shared.NewID()
	assets := []GraphAsset{
		{ID: ipID, Type: assetdom.AssetTypeIPAddress, Name: "203.0.113.11"},
		{
			ID:      shared.NewID(),
			Type:    assetdom.AssetTypeService,
			SubType: "discovered_url",
			Name:    "https://203.0.113.11/login",
			Props:   map[string]any{"host": "203.0.113.11"},
		},
	}
	res := InferGraphEdges(assets)
	if len(res.AutoEdges) != 0 {
		t.Fatalf("discovered_url must not produce Exposes edges, got %+v", res.AutoEdges)
	}
}

// research/531: an address inside a shared provider range is never the
// container of a service, and a name contains the services named by its own
// host name, whatever address they were found on.
func TestInferGraphEdges_ProviderAddressNeverContainer(t *testing.T) {
	nameID, providerID, ownID := shared.NewID(), shared.NewID(), shared.NewID()
	svcByName, svcByURL, svcOnProvider, svcOnOwn := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	assets := []GraphAsset{
		{ID: nameID, Type: assetdom.AssetTypeSubdomain, Name: "mail.example.com"},
		{ID: providerID, Type: assetdom.AssetTypeIPAddress, Name: "13.107.128.10"},
		{ID: ownID, Type: assetdom.AssetTypeIPAddress, Name: "198.51.100.7"},
		{ID: svcByName, Type: assetdom.AssetTypeService, SubType: "open_port", Name: "mail.example.com:443:tcp",
			Props: map[string]any{"host": "13.107.128.10", "port": 443}},
		{ID: svcByURL, Type: assetdom.AssetTypeService, SubType: "http", Name: "https://mail.example.com:443",
			Props: map[string]any{"ip": "13.107.128.10"}},
		{ID: svcOnProvider, Type: assetdom.AssetTypeService, SubType: "open_port", Name: "13.107.128.10:25:tcp",
			Props: map[string]any{"host": "13.107.128.10", "port": 25}},
		{ID: svcOnOwn, Type: assetdom.AssetTypeService, SubType: "open_port", Name: "198.51.100.7:22:tcp",
			Props: map[string]any{"host": "198.51.100.7", "port": 22}},
	}
	res := InferGraphEdges(assets)
	parent := map[shared.ID]shared.ID{}
	for _, e := range append(res.AutoEdges, res.Suggestions...) {
		if e.SourceID == providerID {
			t.Fatalf("a provider address became a container: %+v", e)
		}
		parent[e.TargetID] = e.SourceID
	}
	if parent[svcByName] != nameID || parent[svcByURL] != nameID {
		t.Fatalf("name services' parents = %v / %v, want the name", parent[svcByName], parent[svcByURL])
	}
	if _, ok := parent[svcOnProvider]; ok {
		t.Fatal("a service on a provider address got an inferred parent")
	}
	if parent[svcOnOwn] != ownID {
		t.Fatal("a dedicated address no longer contains its service")
	}
}

func TestServiceNameHost(t *testing.T) {
	for in, want := range map[string]string{
		"api.example.com:443:tcp":       "api.example.com",
		"https://api.example.com:8443/": "api.example.com",
		"http://api.example.com/x":      "api.example.com",
		"api.example.com:443":           "api.example.com",
		"203.0.113.10:22/tcp":           "203.0.113.10",
		"[2001:db8::1]:443":             "2001:db8::1",
		"shop.example.com":              "",
		"2001:db8::1:443:tcp":           "",
	} {
		if got := serviceNameHost(in); got != want {
			t.Errorf("serviceNameHost(%q) = %q, want %q", in, got, want)
		}
	}
}
