package outbox

import (
	"context"

	notificationclient "github.com/openctemio/openctem/api/internal/infra/notifier"
	"github.com/openctemio/openctem/api/pkg/domain/bountyprogram"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	outboxdom "github.com/openctemio/openctem/api/pkg/domain/outbox"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/notifymsg"
)

// Channel messages: one notifymsg.Card per delivery, built from the event,
// the facts of its object and the channel's detail level, then laid out by
// the channel's template. Design: docs/architecture/notification-system.md,
// "Channel messages".

// FactsSource reads, for one tenant, what a message says about an event's
// object. Every method filters on the tenant: an id of another tenant
// resolves to nothing (nil, nil).
type FactsSource interface {
	Organization(ctx context.Context, tenantID shared.ID) (name, language string, err error)
	Finding(ctx context.Context, tenantID, findingID shared.ID) (*notifymsg.Facts, error)
	Exposure(ctx context.Context, tenantID, exposureID shared.ID) (*notifymsg.Facts, error)
	AssetSources(ctx context.Context, tenantID shared.ID, ids []string) ([]notifymsg.AssetRef, error)
}

// SetFactsSource wires the facts lookup. Without it a message carries the
// producer's text only.
func (s *Service) SetFactsSource(f FactsSource) { s.facts = f }

// buildMessage builds the message of one channel. It carries an idempotency
// key derived from the outbox entry ID so provider-side deduplication
// suppresses a duplicate delivery after a worker crash. The names of private
// programs the channel is not attached to are scrubbed from every text value,
// the template's output included.
func (s *Service) buildMessage(ctx context.Context, intg *integration.IntegrationWithNotification, entry *outboxdom.Outbox, delivery bountyprogram.Delivery) notificationclient.Message {
	ext := intg.Notification
	level := notifymsg.LevelMinimal
	if ext != nil {
		level = ext.DetailLevel()
	}
	org, lang := s.organization(ctx, entry.TenantID())
	card := notifymsg.Build(notifymsg.Input{
		EventType:     entry.EventType(),
		AggregateType: entry.AggregateType(),
		Severity:      entry.Severity().String(),
		Level:         level,
		Locale:        lang,
		Organization:  org,
		URL:           deliveryLink(s.linkBase, entry),
		ProducerTitle: entry.Title(),
		ProducerBody:  entry.Body(),
		Facts:         s.eventFacts(ctx, entry, level, lang),
	})
	if ext != nil && ext.MessageTemplate() != "" {
		var ok bool
		if card, ok = notifymsg.ApplyTemplate(card, ext.MessageTemplate()); !ok {
			s.logWarn("notification template no longer valid; default layout used",
				"integration_id", intg.Integration.ID().String())
		}
	}
	id := intg.ID()
	card = card.Map(func(v string) string { return delivery.Scrub(id, v) })
	return notificationclient.Message{
		Title:          card.Headline,
		Body:           card.Text(),
		Severity:       card.Severity,
		URL:            card.Action.URL,
		IdempotencyKey: idempotencyKey(entry),
		EventType:      entry.EventType(),
		EventVersion:   integration.EventPayloadVersion(integration.EventType(entry.EventType())),
		OccurredAt:     entry.CreatedAt(),
		Card:           &card,
	}
}

func (s *Service) logWarn(msg string, args ...any) {
	if s.log != nil {
		s.log.Warn(msg, args...)
	}
}

func (s *Service) organization(ctx context.Context, tenantID shared.ID) (name, language string) {
	if s.facts == nil || tenantID.IsZero() {
		return "", ""
	}
	name, language, err := s.facts.Organization(ctx, tenantID)
	if err != nil {
		s.logWarn("notification: organization unreadable", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		return "", ""
	}
	return name, language
}

// eventFacts reads the facts of the event's object. Object names are read
// only for a channel at standard or above; a lookup error leaves them out
// (the message is never held for it, and never carries more than its level).
func (s *Service) eventFacts(ctx context.Context, entry *outboxdom.Outbox, level notifymsg.Level, locale string) *notifymsg.Facts {
	if entry.EventType() == string(integration.EventTypeNewAsset) {
		return s.assetFacts(ctx, entry, level, locale)
	}
	if s.facts == nil || !level.Includes(notifymsg.LevelStandard) || entry.AggregateID() == nil {
		return nil
	}
	id, err := shared.IDFromString(entry.AggregateID().String())
	if err != nil {
		return nil
	}
	var f *notifymsg.Facts
	switch entry.AggregateType() {
	case "finding":
		f, err = s.facts.Finding(ctx, entry.TenantID(), id)
	case "exposure":
		f, err = s.facts.Exposure(ctx, entry.TenantID(), id)
	default:
		return nil
	}
	if err != nil {
		s.logWarn("notification: facts unreadable", "outbox_id", entry.ID().String(), "error", logger.SanitizeError(err))
		return nil
	}
	return f
}

// assetFacts are the counts of a discovery event (from its metadata, any
// level) and, at standard and above, the listed assets with the names they
// were resolved from.
func (s *Service) assetFacts(ctx context.Context, entry *outboxdom.Outbox, level notifymsg.Level, locale string) *notifymsg.Facts {
	md := entry.Metadata()
	f := &notifymsg.Facts{Count: metaInt(md, "asset_count"), SharedCount: metaInt(md, "shared_count")}
	if p, ok := md["shared_provider"].(string); ok {
		f.SharedProvider = p
	}
	listed := metaAssets(md)
	if f.Count == 0 {
		f.Count = len(listed)
	}
	if !level.Includes(notifymsg.LevelStandard) || len(listed) == 0 {
		return f
	}
	refs := listed
	if s.facts != nil {
		ids := make([]string, 0, len(listed))
		for _, a := range listed {
			ids = append(ids, a.ID)
		}
		got, err := s.facts.AssetSources(ctx, entry.TenantID(), ids)
		if err != nil {
			s.logWarn("notification: assets unreadable", "outbox_id", entry.ID().String(), "error", logger.SanitizeError(err))
		} else {
			refs = mergeSources(listed, got)
		}
	}
	for _, a := range refs {
		f.Items = append(f.Items, a.Text(locale))
	}
	if len(refs) == 1 {
		f.AssetName, f.AssetType = refs[0].Name, refs[0].Type
	}
	return f
}

// mergeSources keeps the order and provider labels of the event's own list
// and takes the current name and source name from the tenant's rows; an
// asset deleted since is left out.
func mergeSources(listed, got []notifymsg.AssetRef) []notifymsg.AssetRef {
	byID := make(map[string]notifymsg.AssetRef, len(got))
	for _, g := range got {
		byID[g.ID] = g
	}
	out := make([]notifymsg.AssetRef, 0, len(listed))
	for _, a := range listed {
		g, ok := byID[a.ID]
		if !ok {
			continue
		}
		g.SharedProvider = a.SharedProvider
		out = append(out, g)
	}
	return out
}

func metaInt(md map[string]any, key string) int {
	switch v := md[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	default:
		return 0
	}
}

// metaAssets reads metadata.assets as written by the asset discovery
// notifier: [{id, name, type, edge_provider}].
func metaAssets(md map[string]any) []notifymsg.AssetRef {
	raw, ok := md["assets"].([]any)
	if !ok {
		if typed, ok := md["assets"].([]map[string]any); ok {
			for _, m := range typed {
				raw = append(raw, m)
			}
		}
	}
	out := make([]notifymsg.AssetRef, 0, len(raw))
	for _, it := range raw {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		a := notifymsg.AssetRef{}
		a.ID, _ = m["id"].(string)
		a.Name, _ = m["name"].(string)
		a.Type, _ = m["type"].(string)
		a.SharedProvider, _ = m["edge_provider"].(string)
		if a.ID != "" {
			out = append(out, a)
		}
	}
	return out
}
