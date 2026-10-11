package ingest

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The connector inventory hook fires only for a report bound to a
// connector_sync command (the command the platform wrote) or a trusted
// server-side ingest that names its integration; never for a scan, an
// unsolicited report, or a sensor that claims to be a connector.
func TestRecordConnectorInventory(t *testing.T) {
	type call struct{ cmd, intg *shared.ID }
	var calls []call
	s := &Service{}
	s.SetConnectorInventoryHook(func(_ context.Context, _ shared.ID, cmd, intg *shared.ID, ids []shared.ID) {
		if len(ids) != 1 {
			t.Fatalf("assets %v", ids)
		}
		calls = append(calls, call{cmd, intg})
	})
	scope := &alterScope{seen: map[shared.ID]seenAsset{shared.NewID(): {}}}
	tenant := shared.NewID()
	cmdID, intgID := shared.NewID(), shared.NewID()

	s.recordConnectorInventory(context.Background(), tenant,
		Binding{Kind: BindingCommand, CommandID: &cmdID, CommandType: command.CommandTypeConnectorSync}, Options{}, scope)
	s.recordConnectorInventory(context.Background(), tenant, TrustedBinding(), Options{IntegrationID: &intgID}, scope)
	if len(calls) != 2 || calls[0].cmd == nil || *calls[0].cmd != cmdID || calls[1].intg == nil || *calls[1].intg != intgID {
		t.Fatalf("calls %+v", calls)
	}

	calls = nil
	other := shared.NewID()
	for _, b := range []struct {
		b    Binding
		opts Options
	}{
		{Binding{Kind: BindingCommand, CommandID: &cmdID, CommandType: command.CommandTypeScan}, Options{IntegrationID: &intgID}},
		{Binding{Kind: BindingUnsolicited}, Options{IntegrationID: &other}},
		{TrustedBinding(), Options{}},
	} {
		s.recordConnectorInventory(context.Background(), tenant, b.b, b.opts, scope)
	}
	if len(calls) != 0 {
		t.Fatalf("hook fired for a non-connector report: %+v", calls)
	}
	// Nothing written: no call.
	s.recordConnectorInventory(context.Background(), tenant,
		Binding{Kind: BindingCommand, CommandID: &cmdID, CommandType: command.CommandTypeConnectorSync}, Options{}, &alterScope{})
	if len(calls) != 0 {
		t.Fatal("hook fired with nothing written")
	}
}
