package outbox

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	outboxdom "github.com/openctemio/openctem/api/pkg/domain/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/notifymsg"
)

// fakeFacts holds rows per tenant: a lookup with another tenant's id finds
// nothing, as the tenant-scoped queries do.
type fakeFacts struct {
	orgs      map[shared.ID][2]string
	exposures map[shared.ID]map[shared.ID]*notifymsg.Facts
	assets    map[shared.ID]map[string]notifymsg.AssetRef
	err       error
}

func (f fakeFacts) Organization(_ context.Context, t shared.ID) (string, string, error) {
	o := f.orgs[t]
	return o[0], o[1], nil
}

func (f fakeFacts) Finding(context.Context, shared.ID, shared.ID) (*notifymsg.Facts, error) {
	return nil, f.err
}

func (f fakeFacts) Exposure(_ context.Context, t, id shared.ID) (*notifymsg.Facts, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.exposures[t][id], nil
}

func (f fakeFacts) AssetSources(_ context.Context, t shared.ID, ids []string) ([]notifymsg.AssetRef, error) {
	var out []notifymsg.AssetRef
	for _, id := range ids {
		if a, ok := f.assets[t][id]; ok {
			out = append(out, a)
		}
	}
	return out, nil
}

func msgChannel(level notifymsg.Level, template string) *integration.IntegrationWithNotification {
	ext := integration.NewNotificationExtension(shared.NewID())
	if level != "" {
		_ = ext.SetDetailLevel(level)
	}
	if template != "" {
		if err := ext.SetMessageTemplate(template); err != nil {
			panic(err)
		}
	}
	return integration.NewIntegrationWithNotification(integration.Reconstruct(shared.NewID(), shared.NewID(), "c", "",
		integration.CategoryNotification, integration.ProviderTelegram, integration.StatusConnected, "", integration.AuthTypeToken,
		"", "", nil, nil, 60, "", nil, nil, integration.Stats{}, time.Now(), time.Now(), nil), ext)
}

func exposureEntry(tenant shared.ID, id shared.ID) *outboxdom.Outbox {
	u := uuid.MustParse(id.String())
	return outboxdom.Reconstitute(outboxdom.NewID(), tenant, "new_exposure", "exposure", &u,
		"New high exposure: Admin panel", "free text", outboxdom.SeverityHigh, "/exposures/"+id.String(),
		nil, outboxdom.OutboxStatusPending, 0, 3, "", time.Time{}, nil, "", time.Time{}, time.Time{}, nil)
}

func TestBuildMessage_StandardChannelNamesTheAssetOnce(t *testing.T) {
	tenant, exp := shared.NewID(), shared.NewID()
	s := &Service{facts: fakeFacts{
		orgs: map[shared.ID][2]string{tenant: {"Acme", "vi"}},
		exposures: map[shared.ID]map[shared.ID]*notifymsg.Facts{tenant: {exp: {
			Title: "Admin panel", Class: "web_interface_exposed", AssetName: "admin.acme.test", AssetType: "subdomain"}}},
	}}
	s.SetLinkBase("https://ctem.example.com")
	m := s.buildMessage(context.Background(), msgChannel(notifymsg.LevelStandard, ""), exposureEntry(tenant, exp), bountyprogram.Delivery{})
	if m.Card == nil || m.Card.Subject.Name != "admin.acme.test" || m.Card.Organization != "Acme" || m.Card.Locale != "vi" {
		t.Fatalf("card: %+v", m.Card)
	}
	if strings.Contains(m.Body, exp.String()) || strings.Contains(m.Body, "http") {
		t.Fatalf("body carries the link or an id: %q", m.Body)
	}
	if !strings.HasPrefix(m.URL, "https://ctem.example.com/exposures/"+exp.String()) {
		t.Fatalf("url %q", m.URL)
	}
}

// Minimal (every channel created before detail levels with details off):
// no object names reach the provider, even when the facts are there.
func TestBuildMessage_MinimalChannelNeverReadsNames(t *testing.T) {
	tenant, exp := shared.NewID(), shared.NewID()
	s := &Service{facts: fakeFacts{exposures: map[shared.ID]map[shared.ID]*notifymsg.Facts{tenant: {exp: {
		Title: "Admin panel", AssetName: "admin.acme.test"}}}}}
	for name, intg := range map[string]*integration.IntegrationWithNotification{
		"minimal":      msgChannel(notifymsg.LevelMinimal, ""),
		"no extension": integration.NewIntegrationWithNotification(msgChannel("", "").Integration, nil),
		// A template cannot reach above the level.
		"template": msgChannel(notifymsg.LevelMinimal, "{asset} {what} {description}"),
	} {
		m := s.buildMessage(context.Background(), intg, exposureEntry(tenant, exp), bountyprogram.Delivery{})
		if strings.Contains(m.Title+m.Body, "admin") || strings.Contains(m.Title+m.Body, "Admin") || strings.Contains(m.Body, "free text") {
			t.Errorf("%s leaks details: %q / %q", name, m.Title, m.Body)
		}
		if m.Title != "New exposure" {
			t.Errorf("%s: headline %q", name, m.Title)
		}
	}
}

// The facts are read inside the event's tenant only: an exposure id of
// another tenant resolves to nothing, and the message falls back to the
// producer's own title for its own tenant.
func TestBuildMessage_FactsAreTenantScoped(t *testing.T) {
	tenantA, tenantB, exp := shared.NewID(), shared.NewID(), shared.NewID()
	s := &Service{facts: fakeFacts{exposures: map[shared.ID]map[shared.ID]*notifymsg.Facts{tenantA: {exp: {
		Title: "Secret of A", AssetName: "a-only.test"}}}}}
	m := s.buildMessage(context.Background(), msgChannel(notifymsg.LevelFull, ""), exposureEntry(tenantB, exp), bountyprogram.Delivery{})
	if strings.Contains(m.Body, "a-only") || strings.Contains(m.Body, "Secret of A") {
		t.Fatalf("tenant B got tenant A's facts: %q", m.Body)
	}
}

// A lookup error never holds the alert and never sends more than the level.
func TestBuildMessage_FactsErrorFallsBack(t *testing.T) {
	s := &Service{facts: fakeFacts{err: errors.New("db down")}}
	m := s.buildMessage(context.Background(), msgChannel(notifymsg.LevelStandard, ""), exposureEntry(shared.NewID(), shared.NewID()), bountyprogram.Delivery{})
	if m.Card == nil || m.Title != "New exposure" {
		t.Fatalf("message %+v", m)
	}
}

// A stored template that no longer validates (the old presets) is not used:
// nothing renders raw braces.
func TestBuildMessage_LegacyTemplateFallsBackToTheDefaultLayout(t *testing.T) {
	ext := integration.ReconstructNotificationExtension(shared.NewID(), "", "", nil, nil,
		"{severity_emoji} [{severity}] {title}\n{body}\n{url}\nTimestamp: {timestamp}", "standard", 5)
	intg := integration.NewIntegrationWithNotification(msgChannel("", "").Integration, ext)
	m := (&Service{}).buildMessage(context.Background(), intg, exposureEntry(shared.NewID(), shared.NewID()), bountyprogram.Delivery{})
	if strings.ContainsAny(m.Body, "{}") || m.Card.Custom != nil {
		t.Fatalf("raw braces or legacy template used: %q", m.Body)
	}
}

// A discovery lists its assets with the names they came from, at most five
// and "+N more", and links to the asset list (the producer's link).
func TestBuildMessage_DiscoveryListsAssetsFromTheirNames(t *testing.T) {
	tenant, other := shared.NewID(), shared.NewID()
	var listed []any
	assets := map[string]notifymsg.AssetRef{}
	for i := range 7 {
		id := shared.NewID().String()
		name := "2603:1000:4::5e" + string(rune('1'+i))
		listed = append(listed, map[string]any{"id": id, "name": name, "type": "ip_address", "edge_provider": "Azure Front Door"})
		assets[id] = notifymsg.AssetRef{ID: id, Name: name, Type: "ip_address", From: "www.acme.test"}
	}
	md := map[string]any{"asset_count": float64(7), "shared_count": float64(7), "shared_provider": "Azure Front Door", "assets": listed}
	entry := outboxdom.Reconstitute(outboxdom.NewID(), tenant, "new_asset", "asset", nil,
		"7 new addresses", "", outboxdom.SeverityMedium, "/assets?internet_facing=true",
		md, outboxdom.OutboxStatusPending, 0, 3, "", time.Time{}, nil, "", time.Time{}, time.Time{}, nil)
	s := &Service{facts: fakeFacts{assets: map[shared.ID]map[string]notifymsg.AssetRef{tenant: assets}}}
	m := s.buildMessage(context.Background(), msgChannel(notifymsg.LevelStandard, ""), entry, bountyprogram.Delivery{})
	if len(m.Card.Items) != notifymsg.MaxItems || m.Card.More != 2 || !strings.Contains(m.Card.Items[0], "from www.acme.test") {
		t.Fatalf("items %q more %d", m.Card.Items, m.Card.More)
	}
	if !strings.Contains(m.Title, "shared provider edge") || !strings.Contains(m.Card.Why, "Azure Front Door") {
		t.Fatalf("headline %q why %q", m.Title, m.Card.Why)
	}

	// The same metadata replayed under another tenant names no source.
	entryB := outboxdom.Reconstitute(outboxdom.NewID(), other, "new_asset", "asset", nil,
		"7 new addresses", "", outboxdom.SeverityMedium, "/assets", md, outboxdom.OutboxStatusPending,
		0, 3, "", time.Time{}, nil, "", time.Time{}, time.Time{}, nil)
	mb := s.buildMessage(context.Background(), msgChannel(notifymsg.LevelStandard, ""), entryB, bountyprogram.Delivery{})
	if strings.Contains(mb.Body, "www.acme.test") {
		t.Fatalf("cross-tenant source name: %q", mb.Body)
	}
}
