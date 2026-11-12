package ingest

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeReceipts struct{ deltas []ingestreceipt.Delta }

func (f *fakeReceipts) Record(_ context.Context, d *ingestreceipt.Delta) (shared.ID, error) {
	f.deltas = append(f.deltas, *d)
	return shared.NewID(), nil
}

// The receipt an ingest counts toward follows its authority: an upload's
// own, the command (resolved to its scan run by the repository), the CI
// run, the connector run, or the sensor's report (hashed, never stored as
// sent).
func TestReceiptSource(t *testing.T) {
	cmd, ci, sensorID := shared.NewID(), shared.NewID(), shared.NewID()
	report := "r-1" // the receiver's report id
	agt := &sensor.Sensor{ID: sensorID}
	upload := ingestreceipt.Source{Kind: ingestreceipt.SourceUpload, Ref: "u"}

	if got := receiptSource(agt, Binding{Kind: BindingTrusted}, Options{Receipt: &upload}, report); got != upload {
		t.Fatalf("explicit receipt: %+v", got)
	}
	if got := receiptSource(agt, Binding{Kind: BindingCommand, CommandID: &cmd}, Options{}, report); got.Kind != ingestreceipt.SourceCommand || got.CommandID == nil || *got.CommandID != cmd {
		t.Fatalf("command: %+v", got)
	}
	if got := receiptSource(agt, CIRunBinding(ci, "repo"), Options{}, report); got.Kind != ingestreceipt.SourceCIRun || got.Ref != ci.String() {
		t.Fatalf("ci run: %+v", got)
	}
	if got := receiptSource(agt, TrustedBinding(), Options{SourceRun: "sync-7"}, report); got.Kind != ingestreceipt.SourceConnector || got.Ref != "sync-7" {
		t.Fatalf("connector: %+v", got)
	}
	got := receiptSource(agt, Binding{Kind: BindingUnsolicited}, Options{}, report)
	if got.Kind != ingestreceipt.SourceSensor || got.Ref != ingestreceipt.ReportRef(sensorID, "r-1") || got.Ref == "r-1" {
		t.Fatalf("unsolicited: %+v", got)
	}
	// Another sensor's report with the same id is another receipt.
	if other := receiptSource(&sensor.Sensor{ID: shared.NewID()}, Binding{Kind: BindingUnsolicited}, Options{}, report); other.Ref == got.Ref {
		t.Fatal("two sensors' reports share a receipt")
	}
}

// What an ingest did becomes one delta: the created and reopened findings by
// id, the sighted ones by fingerprint, closed only for a source's own
// enforced mitigation statement (never in a dry run), skipped without the
// failures, failures as fixed codes.
func TestRecordReceipt_Delta(t *testing.T) {
	rec := &fakeReceipts{}
	svc := &Service{logger: logger.NewNop(), receipts: rec}
	created, reopened, mitigated := shared.NewID(), shared.NewID(), shared.NewID()
	out := &Output{CreatedIDs: []shared.ID{created}, ReopenedIDs: []shared.ID{reopened}, SightedFingerprints: []string{"a", "b"},
		FindingsSkipped: 3, FailedFindings: []FailedFinding{{Index: 4, Error: "pq: secret detail"}},
		SourceResolveIDs: []shared.ID{mitigated}, SourceResolveMode: SourceResolveDryRun}
	report := &ctis.Report{Tool: &ctis.Tool{Name: "nuclei"}, Findings: make([]ctis.Finding, 6)}
	svc.recordReceipt(context.Background(), &sensor.Sensor{ID: shared.NewID()}, shared.NewID(), TrustedBinding(), Options{}, report, out)
	if len(rec.deltas) != 1 || out.ReceiptID == "" {
		t.Fatalf("deltas = %d, receipt %q", len(rec.deltas), out.ReceiptID)
	}
	d := rec.deltas[0]
	if d.Received != 6 || d.Skipped != 2 || d.Failed != 1 || len(d.Created) != 1 || len(d.Reopened) != 1 ||
		len(d.StillDetected) != 2 || len(d.Closed) != 0 || d.Tool != "nuclei" || d.Coverage != "" {
		t.Fatalf("delta = %+v", d)
	}
	if len(d.Errors) != 1 || d.Errors[0].Code != ingestreceipt.ErrorStoreFailed || d.Errors[0].Index != 4 {
		t.Fatalf("errors = %+v (a report's error text must not reach the receipt)", d.Errors)
	}

	out.SourceResolveMode = SourceResolveEnforce
	svc.recordReceipt(context.Background(), &sensor.Sensor{ID: shared.NewID()}, shared.NewID(), TrustedBinding(), Options{}, report, out)
	if c := rec.deltas[1].Closed; len(c) != 1 || c[0] != mitigated {
		t.Fatalf("enforced source mitigation not recorded as closed: %v", c)
	}
}

// A coverage decision is recorded only when it proved coverage; then it
// carries what it closed (nothing in a dry run or when held) and is marked
// full coverage.
func TestRecordCoverageReceipt(t *testing.T) {
	t.Run("enforce", func(t *testing.T) {
		svc, _ := coverageService(t, CoverageAutoResolveEnforce, []string{"nuclei"})
		rec := &fakeReceipts{}
		svc.SetReceiptRecorder(rec)
		cmd := shared.NewID()
		out := svc.EvaluateCommandCoverage(context.Background(), shared.NewID(), cmd)
		if len(rec.deltas) != 1 {
			t.Fatalf("deltas = %d", len(rec.deltas))
		}
		d := rec.deltas[0]
		if d.Coverage != ingestreceipt.CoverageFull || d.CoverageNote != "resolved" || len(d.Closed) != len(out.Resolved) ||
			len(d.Closed) != 1 || d.Source.CommandID == nil || *d.Source.CommandID != cmd || d.Reports != 0 {
			t.Fatalf("delta = %+v", d)
		}
	})
	t.Run("dry run closes nothing", func(t *testing.T) {
		svc, _ := coverageService(t, CoverageAutoResolveDryRun, []string{"nuclei"})
		rec := &fakeReceipts{}
		svc.SetReceiptRecorder(rec)
		svc.EvaluateCommandCoverage(context.Background(), shared.NewID(), shared.NewID())
		if len(rec.deltas) != 1 || len(rec.deltas[0].Closed) != 0 || rec.deltas[0].CoverageNote != "dry_run" {
			t.Fatalf("deltas = %+v", rec.deltas)
		}
	})
	t.Run("not eligible records nothing", func(t *testing.T) {
		svc, repo := coverageService(t, CoverageAutoResolveEnforce, []string{"nuclei"})
		repo.cov.CommandStatus = "failed"
		rec := &fakeReceipts{}
		svc.SetReceiptRecorder(rec)
		svc.EvaluateCommandCoverage(context.Background(), shared.NewID(), shared.NewID())
		if len(rec.deltas) != 0 {
			t.Fatalf("an ineligible run was recorded: %+v", rec.deltas)
		}
	})
}

type failingReceiptStore struct{}

func (failingReceiptStore) Record(context.Context, *ingestreceipt.Delta) (shared.ID, error) {
	return shared.ID{}, errors.New("down")
}

// A receipt that could not be written is flagged on the output, so a
// command-bound segment can be retried rather than leave its findings off
// the receipt that decides absence.
func TestRecordReceipt_FailureIsFlagged(t *testing.T) {
	svc := &Service{logger: logger.NewNop(), receipts: failingReceiptStore{}}
	out := &Output{SightedFingerprints: []string{"a"}}
	svc.recordReceipt(context.Background(), &sensor.Sensor{ID: shared.NewID()}, shared.NewID(), TrustedBinding(), Options{}, &ctis.Report{}, out)
	if !out.ReceiptFailed || out.ReceiptID != "" {
		t.Fatalf("ReceiptFailed = %v, ReceiptID = %q; want true and empty", out.ReceiptFailed, out.ReceiptID)
	}
	ok := &Output{}
	(&Service{logger: logger.NewNop(), receipts: &fakeReceipts{}}).recordReceipt(context.Background(), &sensor.Sensor{ID: shared.NewID()}, shared.NewID(), TrustedBinding(), Options{}, &ctis.Report{}, ok)
	if ok.ReceiptFailed {
		t.Fatal("a recorded receipt was flagged as failed")
	}
}

// Every ingest names its sender: an upload, the CI repository, the
// connector source, or the sensor; a report from no known sender names none.
func TestReceiptInstance(t *testing.T) {
	sensorID := shared.NewID()
	agt := &sensor.Sensor{ID: sensorID}
	report := &ctis.Report{Tool: &ctis.Tool{Name: "trivy"}}
	upload := ingestreceipt.Source{Kind: ingestreceipt.SourceUpload, Ref: "u"}
	for _, tc := range []struct {
		name string
		got  ingestreceipt.Instance
		want ingestreceipt.Instance
	}{
		{"upload", receiptInstance(agt, TrustedBinding(), Options{Receipt: &upload}, report),
			ingestreceipt.Instance{Kind: ingestreceipt.InstanceImport, ID: ingestreceipt.InstanceImport}},
		{"ci run", receiptInstance(&sensor.Sensor{}, CIRunBinding(shared.NewID(), "github.com/acme/app"), Options{}, report),
			ingestreceipt.Instance{Kind: ingestreceipt.InstanceCI, ID: "github.com/acme/app", Name: "github.com/acme/app"}},
		{"connector", receiptInstance(&sensor.Sensor{}, TrustedBinding(), Options{SourceName: "Tenable.sc prod"}, report),
			ingestreceipt.Instance{Kind: ingestreceipt.InstanceConnector, ID: "Tenable.sc prod", Name: "Tenable.sc prod"}},
		{"connector without a name uses the tool", receiptInstance(&sensor.Sensor{}, TrustedBinding(), Options{}, report),
			ingestreceipt.Instance{Kind: ingestreceipt.InstanceConnector, ID: "trivy", Name: "trivy"}},
		{"sensor", receiptInstance(agt, Binding{Kind: BindingUnsolicited}, Options{}, report),
			ingestreceipt.Instance{Kind: ingestreceipt.InstanceSensor, ID: sensorID.String()}},
		{"no sender", receiptInstance(&sensor.Sensor{}, Binding{Kind: BindingUnsolicited}, Options{}, report), ingestreceipt.Instance{}},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, tc.got, tc.want)
		}
	}
}

// A report released from the quarantine counts under the sensor that sent
// it, whatever binding the platform applied it with: the receipt source is a
// sensor report, the sender is that sensor (id and name), and the delta
// carries the release marker.
func TestReceipt_ReleasedItemKeepsItsSender(t *testing.T) {
	sensorID := shared.NewID()
	agt := &sensor.Sensor{ID: sensorID}
	opts := Options{ReleasedFromQuarantine: true, SenderName: "edge-1"}
	src := receiptSource(agt, TrustedBinding(), opts, "rep-9")
	if src.Kind != ingestreceipt.SourceSensor || src.Ref != ingestreceipt.ReportRef(sensorID, "rep-9") {
		t.Fatalf("source = %+v, want the sensor's report", src)
	}
	report := &ctis.Report{Tool: &ctis.Tool{Name: "nuclei"}}
	inst := receiptInstance(agt, TrustedBinding(), opts, report)
	if inst.Kind != ingestreceipt.InstanceSensor || inst.ID != sensorID.String() || inst.Name != "edge-1" {
		t.Fatalf("instance = %+v, want sensor %s edge-1", inst, sensorID)
	}
	if src := receiptSource(agt, TrustedBinding(), Options{}, "rep-9"); src.Kind != ingestreceipt.SourceConnector {
		t.Fatalf("a server-side ingest changed: %+v", src)
	}
	rec := &fakeReceipts{}
	svc := &Service{logger: logger.NewNop(), receipts: rec}
	svc.recordReceipt(context.Background(), agt, shared.NewID(), TrustedBinding(), opts, report, &Output{})
	if len(rec.deltas) != 1 || !rec.deltas[0].Released || rec.deltas[0].Source.Kind != ingestreceipt.SourceSensor {
		t.Fatalf("delta = %+v", rec.deltas)
	}
}

// A report held in the results quarantine reconciles on its receipt: each
// finding is an item and the quarantined outcome, so none is left unexplained.
func TestRecordQuarantined_Reconciles(t *testing.T) {
	rec := &fakeReceipts{}
	svc := &Service{logger: logger.NewNop(), receipts: rec}
	report := &ctis.Report{Tool: &ctis.Tool{Name: "nuclei"}, Findings: []ctis.Finding{
		{RuleID: "a", AssetRef: "h"}, {RuleID: "b", AssetRef: "h"}, {RuleID: "a", AssetRef: "h"}}}
	svc.recordQuarantined(context.Background(), &sensor.Sensor{ID: shared.NewID()}, shared.NewID(), report)
	if len(rec.deltas) != 1 {
		t.Fatalf("deltas %d", len(rec.deltas))
	}
	d := rec.deltas[0]
	if d.Received != 3 || d.Outcomes[ingestreceipt.OutcomeQuarantined] != 3 {
		t.Fatalf("received %d, outcomes %v", d.Received, d.Outcomes)
	}
	if n := ingestreceipt.Unaccounted(d.Received, ingestreceipt.Counts{}, d.Outcomes); n != 0 {
		t.Fatalf("%d unaccounted", n)
	}
}

// A finding that failed to store is counted once, as failed, even when a
// row with its key exists (it is not also still detected).
func TestRecordReceipt_FailedIsNotStillDetected(t *testing.T) {
	rec := &fakeReceipts{}
	svc := &Service{logger: logger.NewNop(), receipts: rec}
	out := &Output{SightedFingerprints: []string{"a", "b"}, FailedFindings: []FailedFinding{{Fingerprint: "b"}}, FindingsSkipped: 1}
	svc.recordReceipt(context.Background(), &sensor.Sensor{ID: shared.NewID()}, shared.NewID(), TrustedBinding(), Options{},
		&ctis.Report{Findings: make([]ctis.Finding, 2)}, out)
	d := rec.deltas[0]
	if len(d.StillDetected) != 1 || d.StillDetected[0] != "a" || d.Failed != 1 || d.Skipped != 0 {
		t.Fatalf("still %v, failed %d, skipped %d", d.StillDetected, d.Failed, d.Skipped)
	}
}
