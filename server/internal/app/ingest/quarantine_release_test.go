package ingest

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// heldStore is an in-memory quarantine honoring the tenant/sensor filters the
// real queries apply.
type heldStore struct {
	sensorresult.Repository
	items map[shared.ID]*sensorresult.Item
}

func (h *heldStore) pending(it *sensorresult.Item, tenant, sensorID *shared.ID) bool {
	return it.Status == sensorresult.StatusPending && it.Reason == sensorresult.ReasonOutOfContract &&
		(tenant == nil || it.TenantID == *tenant) && (sensorID == nil || it.SensorID == *sensorID)
}

func (h *heldStore) PendingOutOfContractGroups(_ context.Context, _ time.Time, tenant, sensorID *shared.ID, _ int) ([]sensorresult.HeldGroup, error) {
	seen := map[sensorresult.HeldGroup]bool{}
	var out []sensorresult.HeldGroup
	for _, it := range h.items {
		g := sensorresult.HeldGroup{TenantID: it.TenantID, SensorID: it.SensorID, ToolName: it.ToolName}
		if h.pending(it, tenant, sensorID) && !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	return out, nil
}

func (h *heldStore) PendingInGroup(_ context.Context, g sensorresult.HeldGroup, _, afterCreated time.Time, afterID shared.ID, _ int) ([]sensorresult.HeldRef, error) {
	var out []sensorresult.HeldRef
	for _, it := range h.items {
		if h.pending(it, &g.TenantID, &g.SensorID) && it.ToolName == g.ToolName && it.CreatedAt.After(afterCreated) {
			out = append(out, sensorresult.HeldRef{ID: it.ID, CreatedAt: it.CreatedAt})
		}
	}
	return out, nil
}

func (h *heldStore) Get(_ context.Context, tenant, id shared.ID) (*sensorresult.Item, error) {
	it, ok := h.items[id]
	if !ok || it.TenantID != tenant {
		return nil, sensorresult.ErrNotFound
	}
	c := *it
	return &c, nil
}

type fakeManifests struct {
	byKey map[shared.ID]*sensor.ManifestVersion
}

func (f *fakeManifests) CurrentManifest(_ context.Context, _ *shared.ID, id shared.ID) (*sensor.ManifestVersion, error) {
	if v, ok := f.byKey[id]; ok {
		return v, nil
	}
	return nil, shared.ErrNotFound
}

func manifestWith(source string, produces []string, descriptor bool) *sensor.ManifestVersion {
	c := &sensor.ToolContract{Digest: "sha256:" + string(make([]byte, 0)) + "a", Produces: produces}
	if descriptor {
		c.Descriptor = json.RawMessage(`{"name":"nuclei"}`)
	}
	return &sensor.ManifestVersion{Source: source, Manifest: sensor.Manifest{Tools: []sensor.ManifestTool{{Name: "nuclei", Contract: c}}}}
}

func webOriginPayload(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(&ctis.Report{
		Tool:     &ctis.Tool{Name: "nuclei"},
		Assets:   []ctis.Asset{{ID: "a1", Type: ctis.AssetTypeWebOrigin, Value: "https://acme.test"}},
		Findings: []ctis.Finding{{Title: "x", AssetRef: "a1", Type: ctis.FindingTypeVulnerability}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type releaseEnv struct {
	s         *Service
	store     *heldStore
	manifests *fakeManifests
	applied   []shared.ID
	reasons   []string
}

func newReleaseEnv(t *testing.T) *releaseEnv {
	t.Helper()
	e := &releaseEnv{store: &heldStore{items: map[shared.ID]*sensorresult.Item{}}, manifests: &fakeManifests{byKey: map[shared.ID]*sensor.ManifestVersion{}}}
	e.s = &Service{logger: logger.NewNop(), results: e.store, contracts: e.manifests}
	e.s.release.apply = func(_ context.Context, _ shared.ID, it *sensorresult.Item, reason string) error {
		e.store.items[it.ID].Status = sensorresult.StatusAccepted
		e.applied = append(e.applied, it.ID)
		e.reasons = append(e.reasons, reason)
		return nil
	}
	return e
}

func (e *releaseEnv) hold(t *testing.T, tenant, sensorID shared.ID, reason sensorresult.Reason) *sensorresult.Item {
	t.Helper()
	it := &sensorresult.Item{ID: shared.NewID(), TenantID: tenant, SensorID: sensorID, ToolName: "nuclei", Reason: reason,
		Status: sensorresult.StatusPending, Payload: webOriginPayload(t), CreatedAt: time.Now()}
	e.store.items[it.ID] = it
	return it
}

func TestRelease_OnlyWhenTypesNowDeclared(t *testing.T) {
	e := newReleaseEnv(t)
	tenant, sn := shared.NewID(), shared.NewID()
	it := e.hold(t, tenant, sn, sensorresult.ReasonOutOfContract)

	// The descriptor still lacks asset:web_origin: nothing is released.
	e.manifests.byKey[sn] = manifestWith(sensor.ManifestSourceSensor, []string{"asset:domain", "finding:vulnerability"}, true)
	if st, _ := e.s.ReleaseOutOfContract(context.Background(), ReleaseOptions{}); st.Released != 0 || len(e.applied) != 0 {
		t.Fatalf("released without a declaration: %+v", st)
	}
	// 0.37.1: web_origin is declared (a new digest, so the cursor restarts).
	m := manifestWith(sensor.ManifestSourceSensor, []string{"asset:domain", "asset:web_origin", "finding:vulnerability"}, true)
	m.Manifest.Tools[0].Contract.Digest = "sha256:b"
	e.manifests.byKey[sn] = m
	st, err := e.s.ReleaseOutOfContract(context.Background(), ReleaseOptions{})
	if err != nil || st.Released != 1 || len(e.applied) != 1 || e.applied[0] != it.ID {
		t.Fatalf("stats %+v err %v applied %v", st, err, e.applied)
	}
	if want := "the tool's signed descriptor now declares asset:web_origin, finding:"; len(e.reasons[0]) < len(want) || e.reasons[0][:len(want)] != want {
		t.Fatalf("reason = %q", e.reasons[0])
	}
}

func TestRelease_OtherTenantOrSensorUntouched(t *testing.T) {
	e := newReleaseEnv(t)
	tenantA, tenantB := shared.NewID(), shared.NewID()
	snA, snB := shared.NewID(), shared.NewID()
	mine := e.hold(t, tenantA, snA, sensorresult.ReasonOutOfContract)
	otherTenant := e.hold(t, tenantB, snB, sensorresult.ReasonOutOfContract)
	otherSensor := e.hold(t, tenantA, snB, sensorresult.ReasonOutOfContract)
	// Only sensor A declares it; sensor B's descriptor does not.
	e.manifests.byKey[snA] = manifestWith(sensor.ManifestSourceSensor, []string{"asset:web_origin", "finding:vulnerability"}, true)
	e.manifests.byKey[snB] = manifestWith(sensor.ManifestSourceSensor, []string{"asset:domain"}, true)

	// The descriptor-change trigger for tenant A / sensor A touches only it.
	if _, err := e.s.ReleaseOutOfContract(context.Background(), ReleaseOptions{TenantID: &tenantA, SensorID: &snA}); err != nil {
		t.Fatal(err)
	}
	if len(e.applied) != 1 || e.applied[0] != mine.ID {
		t.Fatalf("applied %v, want only %v", e.applied, mine.ID)
	}
	for _, it := range []*sensorresult.Item{otherTenant, otherSensor} {
		if e.store.items[it.ID].Status != sensorresult.StatusPending {
			t.Fatalf("item %v of another tenant/sensor changed", it.ID)
		}
	}
	// A sweep with sensor B's own descriptor declares nothing for it either.
	if _, err := e.s.ReleaseOutOfContract(context.Background(), ReleaseOptions{}); err != nil || len(e.applied) != 1 {
		t.Fatalf("sweep applied %v err %v", e.applied, err)
	}
}

func TestRelease_UnsignedOrUnverifiedNeverReleases(t *testing.T) {
	cases := map[string]*sensor.ManifestVersion{
		"derived from a heartbeat":    manifestWith(sensor.ManifestSourceHeartbeat, []string{"asset:web_origin", "finding:vulnerability"}, true),
		"descriptor not kept":         manifestWith(sensor.ManifestSourceSensor, []string{"asset:web_origin", "finding:vulnerability"}, false),
		"no contract for the tool":    {Source: sensor.ManifestSourceSensor, Manifest: sensor.Manifest{Tools: []sensor.ManifestTool{{Name: "nuclei"}}}},
		"a different tool's contract": {Source: sensor.ManifestSourceSensor, Manifest: sensor.Manifest{Tools: []sensor.ManifestTool{{Name: "httpx", Contract: manifestWith(sensor.ManifestSourceSensor, []string{"asset:web_origin"}, true).Manifest.Tools[0].Contract}}}},
	}
	for name, mv := range cases {
		t.Run(name, func(t *testing.T) {
			e := newReleaseEnv(t)
			tenant, sn := shared.NewID(), shared.NewID()
			e.hold(t, tenant, sn, sensorresult.ReasonOutOfContract)
			e.manifests.byKey[sn] = mv
			if st, _ := e.s.ReleaseOutOfContract(context.Background(), ReleaseOptions{}); st.Released != 0 || len(e.applied) != 0 {
				t.Fatalf("released: %+v", st)
			}
		})
	}
	// No manifest at all.
	e := newReleaseEnv(t)
	e.hold(t, shared.NewID(), shared.NewID(), sensorresult.ReasonOutOfContract)
	if _, _ = e.s.ReleaseOutOfContract(context.Background(), ReleaseOptions{}); len(e.applied) != 0 {
		t.Fatal("released without a manifest")
	}
}

func TestRelease_OtherReasonsUntouched(t *testing.T) {
	e := newReleaseEnv(t)
	tenant, sn := shared.NewID(), shared.NewID()
	noCmd := e.hold(t, tenant, sn, sensorresult.ReasonNoCommand)
	e.manifests.byKey[sn] = manifestWith(sensor.ManifestSourceSensor, []string{"asset:web_origin", "finding:vulnerability"}, true)
	_, _ = e.s.ReleaseOutOfContract(context.Background(), ReleaseOptions{})
	if len(e.applied) != 0 || e.store.items[noCmd.ID].Status != sensorresult.StatusPending {
		t.Fatal("a no_command item was released")
	}
	// Even if a store returned it, the per-item guard refuses it.
	g := sensorresult.HeldGroup{TenantID: tenant, SensorID: sn, ToolName: "nuclei"}
	rules := outputRules{declared: e.manifests.byKey[sn].Manifest.Tools[0].Contract}
	if e.s.releaseOne(context.Background(), g, noCmd.ID, rules) != releaseKept || len(e.applied) != 0 {
		t.Fatal("the per-item guard released a no_command item")
	}
}

func TestRelease_StillOutOfContractStaysHeld(t *testing.T) {
	e := newReleaseEnv(t)
	tenant, sn := shared.NewID(), shared.NewID()
	it := e.hold(t, tenant, sn, sensorresult.ReasonOutOfContract)
	// The payload also carries a type the descriptor does not declare.
	var rep ctis.Report
	_ = json.Unmarshal(it.Payload, &rep)
	rep.Assets = append(rep.Assets, ctis.Asset{ID: "a2", Type: ctis.AssetTypeRepository, Value: "github.com/x/y"})
	it.Payload, _ = json.Marshal(&rep)
	e.manifests.byKey[sn] = manifestWith(sensor.ManifestSourceSensor, []string{"asset:web_origin", "finding:vulnerability"}, true)
	if st, _ := e.s.ReleaseOutOfContract(context.Background(), ReleaseOptions{}); st.Released != 0 || st.Kept != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestRelease_SecondRunIsIdempotent(t *testing.T) {
	e := newReleaseEnv(t)
	tenant, sn := shared.NewID(), shared.NewID()
	e.hold(t, tenant, sn, sensorresult.ReasonOutOfContract)
	e.manifests.byKey[sn] = manifestWith(sensor.ManifestSourceSensor, []string{"asset:web_origin", "finding:vulnerability"}, true)
	for i := 0; i < 3; i++ {
		_, _ = e.s.ReleaseOutOfContract(context.Background(), ReleaseOptions{})
	}
	if len(e.applied) != 1 {
		t.Fatalf("applied %d times", len(e.applied))
	}
}

func TestRelease_BoundedPerRun(t *testing.T) {
	e := newReleaseEnv(t)
	tenant, sn := shared.NewID(), shared.NewID()
	for i := 0; i < 5; i++ {
		it := e.hold(t, tenant, sn, sensorresult.ReasonOutOfContract)
		it.CreatedAt = time.Now().Add(time.Duration(i) * time.Second)
	}
	e.manifests.byKey[sn] = manifestWith(sensor.ManifestSourceSensor, []string{"asset:web_origin", "finding:vulnerability"}, true)
	st, _ := e.s.ReleaseOutOfContract(context.Background(), ReleaseOptions{Budget: 2})
	if st.Examined != 2 || st.Released != 2 {
		t.Fatalf("stats %+v", st)
	}
}
