package ingest

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type recordedOutputs struct {
	tenant, stepRun shared.ID
	ids             []shared.ID
	calls           int
}

func (r *recordedOutputs) RecordStepOutputs(_ context.Context, tenantID, stepRunID shared.ID, ids []shared.ID) (int, error) {
	r.calls++
	r.tenant, r.stepRun, r.ids = tenantID, stepRunID, ids
	return len(ids), nil
}

// What a command-bound report of a pipeline step wrote is recorded for the
// step the binding names (server-side), under the ingest's tenant; an
// unsolicited report, a trusted ingest and a command outside a pipeline
// record nothing.
func TestRecordStepOutputs(t *testing.T) {
	rec := &recordedOutputs{}
	s := &Service{logger: logger.NewNop(), stepOutputs: rec}
	tenant, stepRun := shared.NewID(), shared.NewID()
	scope := &alterScope{seen: map[shared.ID]seenAsset{}}
	a, b := shared.NewID(), shared.NewID()
	scope.seen[a] = seenAsset{created: true, name: "x.acme.test", typ: asset.TypeRef{Type: asset.AssetTypeSubdomain}}
	scope.seen[b] = seenAsset{name: "acme.test", typ: asset.TypeRef{Type: asset.AssetTypeDomain}}

	s.recordStepOutputs(context.Background(), tenant, Binding{Kind: BindingCommand, StepRunID: &stepRun}, scope)
	if rec.calls != 1 || rec.tenant != tenant || rec.stepRun != stepRun || len(rec.ids) != 2 {
		t.Fatalf("recorded %+v", rec)
	}
	for _, b := range []Binding{
		{Kind: BindingUnsolicited, StepRunID: &stepRun},
		{Kind: BindingTrusted, StepRunID: &stepRun},
		{Kind: BindingCommand},
	} {
		s.recordStepOutputs(context.Background(), tenant, b, scope)
	}
	if rec.calls != 1 {
		t.Fatalf("recorded for a report that is not bound to a pipeline step (%d calls)", rec.calls)
	}
}

// The command-ingested hook fires only for a report that names a command.
func TestCommandIngestedNow(t *testing.T) {
	var got []shared.ID
	s := &Service{logger: logger.NewNop()}
	s.SetCommandIngestedHook(func(_ context.Context, _ shared.ID, cmd shared.ID) { got = append(got, cmd) })
	cmd := shared.NewID()
	s.commandIngestedNow(context.Background(), shared.NewID(), &cmd)
	s.commandIngestedNow(context.Background(), shared.NewID(), nil)
	if len(got) != 1 || got[0] != cmd {
		t.Fatalf("hook calls = %v", got)
	}
}
