package ingest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/command"
	"github.com/openctemio/openctem/server/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type fakeGrants struct{ trust sensor.TrustLevel }

func (f fakeGrants) Get(_ context.Context, tenantID, sensorID shared.ID) (*sensor.Grant, error) {
	if f.trust == "" {
		return nil, shared.ErrNotFound
	}
	return &sensor.Grant{TenantID: tenantID, SensorID: sensorID, TrustLevel: f.trust}, nil
}

type recordingNotifier struct {
	mu       sync.Mutex
	subjects []string
}

func (n *recordingNotifier) NotifyAdmins(_ context.Context, subject, _ string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.subjects = append(n.subjects, subject)
	return nil
}

func (n *recordingNotifier) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.subjects)
}

type mismatchEnv struct {
	s        *Service
	results  *policyResults
	notifier *recordingNotifier
	tenant   shared.ID
	agt      *sensor.Sensor
}

// newMismatchEnv: a tenant in quarantine mode, one sensor, nuclei's
// descriptor that does not declare asset:web_origin.
func newMismatchEnv(t *testing.T, origin string, source string, trust sensor.TrustLevel) *mismatchEnv {
	t.Helper()
	tenant := shared.NewID()
	agt := &sensor.Sensor{ID: shared.NewID(), TenantID: &tenant}
	c := &sensor.ToolContract{Digest: "sha256:a", Version: "3.4.0", Origin: origin,
		Produces: []string{"asset:domain_name", "finding:vulnerability"}, Descriptor: []byte(`{"name":"nuclei"}`)}
	mv := &sensor.ManifestVersion{Source: source, Manifest: sensor.Manifest{Tools: []sensor.ManifestTool{{Name: "nuclei", Contract: c}}}}
	res := &policyResults{mode: sensorresult.ModeQuarantine}
	n := &recordingNotifier{}
	s := &Service{logger: logger.NewNop(), results: res,
		contracts: &fakeManifests{byKey: map[shared.ID]*sensor.ManifestVersion{agt.ID: mv}},
		grants:    fakeGrants{trust: trust}}
	s.SetMismatchNotifier(n)
	return &mismatchEnv{s: s, results: res, notifier: n, tenant: tenant, agt: agt}
}

func nucleiBinding() Binding {
	id := shared.NewID()
	return Binding{Kind: BindingCommand, CommandID: &id, Tool: "nuclei", Targets: []string{"acme.test"}, CommandType: command.CommandTypeScan}
}

func nucleiReport() *ctis.Report {
	return &ctis.Report{
		Metadata: ctis.ReportMetadata{ID: "r1"},
		Tool:     &ctis.Tool{Name: "nuclei"},
		Assets: []ctis.Asset{
			{ID: "in", Type: ctis.AssetTypeWebOrigin, Value: "https://app.acme.test"},
			{ID: "out", Type: ctis.AssetTypeWebOrigin, Value: "https://evil.example"},
		},
		Findings: []ctis.Finding{
			{Title: "on scope", AssetRef: "in", Type: ctis.FindingTypeVulnerability},
			{Title: "off scope", AssetRef: "out", Type: ctis.FindingTypeVulnerability},
		},
	}
}

func (e *mismatchEnv) bind(r *ctis.Report) (*ctis.Report, *contractMismatch) {
	kept, _, _, _, flagged := e.s.bindOutputTypesFlagged(context.Background(), e.agt, e.tenant, nucleiBinding(), r, Options{Route: "ctis"})
	return kept, flagged
}

func refsOf(r *ctis.Report) map[string]bool {
	m := map[string]bool{}
	for _, a := range r.Assets {
		m[a.ID] = true
	}
	return m
}

// A verified first-party mismatch inside the job's targets is ingested and
// flagged; the part outside the targets is still held.
func TestContractMismatch_FirstPartyInScopeIsIngestedAndFlagged(t *testing.T) {
	e := newMismatchEnv(t, sensor.ToolOriginBuiltin, sensor.ManifestSourceSensor, sensor.TrustTrusted)
	got, flagged := e.bind(nucleiReport())
	if refs := refsOf(got); !refs["in"] || refs["out"] || len(got.Findings) != 1 || got.Findings[0].AssetRef != "in" {
		t.Fatalf("applied assets %v findings %d", refs, len(got.Findings))
	}
	if flagged == nil || len(flagged.Types) != 1 || flagged.Types[0] != "asset:web_origin" || !flagged.AssetRefs["in"] {
		t.Fatalf("flagged = %+v", flagged)
	}
	if len(e.results.items) != 1 || e.results.items[0].AssetsCount != 1 || e.results.items[0].Reason != sensorresult.ReasonOutOfContract {
		t.Fatalf("the out-of-scope asset was not held: %+v", e.results.items)
	}
	// One notice for (tool, type, version); a second report adds none.
	waitFor(t, func() bool { return e.notifier.count() == 1 })
	e.bind(nucleiReport())
	time.Sleep(50 * time.Millisecond)
	if n := e.notifier.count(); n != 1 {
		t.Fatalf("%d notices, want 1 (deduplicated)", n)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

// Anything but a verified first-party tool on a trusted sensor keeps the hold.
func TestContractMismatch_UnverifiedStaysHeld(t *testing.T) {
	cases := map[string]*mismatchEnv{
		"third-party (adapter) tool": newMismatchEnv(t, sensor.ToolOriginAdapter, sensor.ManifestSourceSensor, sensor.TrustTrusted),
		"descriptor not from sensor": newMismatchEnv(t, sensor.ToolOriginBuiltin, sensor.ManifestSourceHeartbeat, sensor.TrustTrusted),
		"sensor not trusted":         newMismatchEnv(t, sensor.ToolOriginBuiltin, sensor.ManifestSourceSensor, sensor.TrustNew),
		"sensor without a grant":     newMismatchEnv(t, sensor.ToolOriginBuiltin, sensor.ManifestSourceSensor, ""),
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			got, flagged := e.bind(nucleiReport())
			if flagged != nil || len(got.Assets) != 0 || len(got.Findings) != 0 {
				t.Fatalf("applied %d assets, flagged %+v", len(got.Assets), flagged)
			}
			if len(e.results.items) != 1 || e.results.items[0].AssetsCount != 2 {
				t.Fatalf("held = %+v", e.results.items)
			}
			if e.notifier.count() != 0 {
				t.Fatal("an administrator notice for a held report")
			}
		})
	}
}

// A sensor of another tenant never gets the first-party path.
func TestContractMismatch_OtherTenantSensorStaysHeld(t *testing.T) {
	e := newMismatchEnv(t, sensor.ToolOriginBuiltin, sensor.ManifestSourceSensor, sensor.TrustTrusted)
	other := shared.NewID()
	got, _, _, _, flagged := e.s.bindOutputTypesFlagged(context.Background(), e.agt, other, nucleiBinding(), nucleiReport(), Options{Route: "ctis"})
	if flagged != nil || len(got.Assets) != 0 {
		t.Fatalf("cross-tenant report applied: %d assets, %+v", len(got.Assets), flagged)
	}
}

// No target, an asset with no location to check, or an address outside every
// target: held.
func TestContractMismatch_OutOfScopeOrUnlocatedStaysHeld(t *testing.T) {
	e := newMismatchEnv(t, sensor.ToolOriginBuiltin, sensor.ManifestSourceSensor, sensor.TrustTrusted)
	b := nucleiBinding()
	b.Targets = nil
	got, _, _, _, flagged := e.s.bindOutputTypesFlagged(context.Background(), e.agt, e.tenant, b, nucleiReport(), Options{Route: "ctis"})
	if flagged != nil || len(got.Assets) != 0 {
		t.Fatalf("a command without targets let %d assets through", len(got.Assets))
	}
	r := &ctis.Report{Tool: &ctis.Tool{Name: "nuclei"}, Assets: []ctis.Asset{
		{ID: "ip", Type: ctis.AssetTypeWebOrigin, Value: "http://203.0.113.9"},
	}}
	if got, flagged := e.bind(r); flagged != nil || len(got.Assets) != 0 {
		t.Fatalf("an address outside the targets was applied: %+v", got.Assets)
	}
}

// A declared type is unchanged: nothing is flagged, nothing is noticed.
func TestContractMismatch_DeclaredTypeIsNotAMismatch(t *testing.T) {
	e := newMismatchEnv(t, sensor.ToolOriginBuiltin, sensor.ManifestSourceSensor, sensor.TrustTrusted)
	r := &ctis.Report{Tool: &ctis.Tool{Name: "nuclei"},
		Assets:   []ctis.Asset{{ID: "d", Type: ctis.AssetTypeDomainName, Value: "app.acme.test"}},
		Findings: []ctis.Finding{{Title: "t", AssetRef: "d", Type: ctis.FindingTypeVulnerability}}}
	got, flagged := e.bind(r)
	if flagged != nil || len(got.Assets) != 1 || len(e.results.items) != 0 {
		t.Fatalf("flagged %+v assets %d held %d", flagged, len(got.Assets), len(e.results.items))
	}
}

func TestMismatchNotices_DedupPerKeyForADay(t *testing.T) {
	now := time.Now()
	m := &mismatchNotices{now: func() time.Time { return now }}
	if !m.due("nuclei|asset:web_origin|3.4.0") || m.due("nuclei|asset:web_origin|3.4.0") {
		t.Fatal("same key must be due once")
	}
	if !m.due("nuclei|asset:web_origin|3.5.0") {
		t.Fatal("another version is its own notice")
	}
	now = now.Add(25 * time.Hour)
	if !m.due("nuclei|asset:web_origin|3.4.0") {
		t.Fatal("the notice is due again after 24h")
	}
}

type recordedReceipts struct{ deltas []*ingestreceipt.Delta }

func (r *recordedReceipts) Record(_ context.Context, d *ingestreceipt.Delta) (shared.ID, error) {
	r.deltas = append(r.deltas, d)
	return shared.NewID(), nil
}

// The receipt flags each finding of a mismatched asset.
func TestContractMismatch_ReceiptErrorsNameTheFindings(t *testing.T) {
	rec := &recordedReceipts{}
	s := &Service{logger: logger.NewNop(), receipts: rec}
	rep := nucleiReport()
	rep.Assets, rep.Findings = rep.Assets[:1], rep.Findings[:1]
	out := &Output{ContractMismatchTypes: []string{"asset:web_origin"}, ContractMismatchRefs: map[string]bool{"in": true}}
	s.recordReceipt(context.Background(), &sensor.Sensor{ID: shared.NewID()}, shared.NewID(), nucleiBinding(), Options{}, rep, out)
	if len(rec.deltas) != 1 || len(rec.deltas[0].Errors) != 1 ||
		rec.deltas[0].Errors[0].Code != ingestreceipt.ErrorContractMismatch || rec.deltas[0].Errors[0].Index != 0 {
		t.Fatalf("errors = %+v", rec.deltas)
	}
}
