package easm

import (
	"context"
	"testing"

	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/scangov"
	scopedom "github.com/openctemio/openctem/server/pkg/domain/scope"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type fakeTouched map[string][]shared.ID // command id -> assets

func (f fakeTouched) TouchedAssetsByCommand(_ context.Context, _, commandID shared.ID) ([]shared.ID, error) {
	return f[commandID.String()], nil
}

type fakeNotifier struct {
	titles []string
	msgs   []*notificationdom.Message
}

func (f *fakeNotifier) NotifyAdminsMsg(_ context.Context, _ shared.ID, title, _ string, msg *notificationdom.Message) {
	f.titles = append(f.titles, title)
	f.msgs = append(f.msgs, msg)
}

type countingAudit struct{ n int }

func (c *countingAudit) LogEvent(context.Context, auditapp.AuditContext, auditapp.AuditEvent) error {
	c.n++
	return nil
}

func TestConnectorScope_AddsExactEntriesOfSyncedAssets(t *testing.T) {
	tenantID := shared.NewID()
	assets := &confirmAssets{tenant: tenantID, byID: map[string]*asset.Asset{}}
	ids := []string{
		assets.add(t, "203.0.113.30", asset.AssetTypeIPAddress),
		assets.add(t, "app.corp.example", asset.AssetTypeSubdomain),
		assets.add(t, "10.1.2.3", asset.AssetTypeIPAddress),       // private: zones gate it
		assets.add(t, "a.ours.example", asset.AssetTypeSubdomain), // already covered
		assets.add(t, "203.0.113.30:443", asset.AssetTypeService), // follows its host
		assets.add(t, "db01", asset.AssetTypeHost),                // not a public name
	}
	cmd := shared.NewID()
	touched := fakeTouched{cmd.String(): toIDs(t, ids)}
	targets := &fakeConfirmTargets{mode: scangov.ModeOff}
	notify := &fakeNotifier{}
	audit := &countingAudit{}
	c := NewConnectorScope(targets, notify, assets, fakeCover{}, touched, audit, logger.NewNop())

	n, err := c.AddConnectorAssets(context.Background(), tenantID, "sc", cmd)
	if err != nil || n != 2 {
		t.Fatalf("added %d, %v; want 2", n, err)
	}
	in := targets.calls[0]
	if in.Origin != scopedom.OriginConnector || in.Actor.UserID != "" || in.CreatedBy != "" {
		t.Fatalf("batch %+v: origin connector, system actor", in)
	}
	got := map[string]string{}
	for _, it := range in.Items {
		got[it.Pattern] = it.TargetType
	}
	if len(got) != 2 || got["203.0.113.30"] != "ip_address" || got["app.corp.example"] != "domain" {
		t.Fatalf("items %v", got)
	}
	if len(notify.titles) != 1 || audit.n != 2 {
		t.Fatalf("notices %v audit events %d", notify.titles, audit.n)
	}
	if m := notify.msgs[0]; m == nil || m.Code != "connector.scope_added" || m.Params["count"] != 2 || m.Params["connector"] != "sc" ||
		m.Params["entries"] != "203.0.113.30, app.corp.example" && m.Params["entries"] != "app.corp.example, 203.0.113.30" {
		t.Fatalf("added message = %+v", m)
	}

	// Another tenant: the same command reads nothing of this tenant's.
	targets.calls = nil
	if n, err := c.AddConnectorAssets(context.Background(), shared.NewID(), "sc", cmd); err != nil || n != 0 || len(targets.calls) != 0 {
		t.Fatalf("another tenant: %d %v %d", n, err, len(targets.calls))
	}
	// Strict adds nothing.
	strict := NewConnectorScope(&fakeConfirmTargets{mode: scangov.ModeStrict}, notify, assets, fakeCover{}, touched, nil, logger.NewNop())
	if n, err := strict.AddConnectorAssets(context.Background(), tenantID, "sc", cmd); err != nil || n != 0 {
		t.Fatalf("strict: %d %v", n, err)
	}
	// The one-time notice names the connector.
	c.NotifyConnectorScope(context.Background(), tenantID, "sc")
	if notify.titles[len(notify.titles)-1] != "Assets from sc will be added to scope" {
		t.Fatalf("notice %v", notify.titles)
	}
	if m := notify.msgs[len(notify.msgs)-1]; m == nil || m.Code != "connector.scope_planned" || m.Params["connector"] != "sc" {
		t.Fatalf("planned message = %+v", m)
	}
}

func toIDs(t *testing.T, raw []string) []shared.ID {
	t.Helper()
	out := make([]shared.ID, 0, len(raw))
	for _, r := range raw {
		id, err := shared.IDFromString(r)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	return out
}
