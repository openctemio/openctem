package easmdns

// Subdomain-takeover confirmation (RFC-036 P1, §6.8): the DNS-only check
// raises dangling_cname at medium with "confirmation: pending". A nuclei
// takeover template that matches the same name, run by the tenant's own
// scan, confirms it: the platform raises subdomain_takeover (high) and marks
// the dangling_cname confirmed.
//
// A provider that serves names from shared front ends (its CNAME target
// always resolves) answers for a name nobody claims with its own "not
// configured" page, which the DNS check cannot see. A takeover template match
// on a name with no open dangling_cname therefore also counts when the
// platform's resolver shows the name's CNAME chain ending at a provider of
// the fingerprint lists: the confirmer raises the dangling_cname itself
// (response class provider_unclaimed_page, confirmed) with the takeover.
//
// No probe is sent from here. The confirming request is a tenant scan, which
// went through the scan gate (scope, exclusions, attribution, zones; see
// docs/architecture/active-probe-gate.md) before any command existed, and
// ingest only hands over findings of a report bound to that command, on
// assets the command covered (RFC-040 §5.3). A takeover template match
// without an open dangling_cname for the name confirms nothing: the HTTP
// fingerprint alone is not enough for a high.

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/dnsprobe"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// TakeoverSighting is one nuclei takeover-template match on an asset.
type TakeoverSighting struct {
	AssetID    shared.ID
	TemplateID string
	Matched    string
	SensorID   shared.ID
	CommandID  *shared.ID
}

// OpenDangling is an active dangling_cname exposure this check raised.
type OpenDangling struct {
	ExposureID string
	AssetID    shared.ID
	Name       string // details.domain
	Target     string
	Provider   string
	// ResponseClass is details.response_class; empty on exposures raised
	// before it existed (they are the DNS-only, NXDOMAIN-target kind).
	ResponseClass string
}

// TakeoverStore is the persistence confirmation needs. Tenant-scoped.
type TakeoverStore interface {
	// OpenDanglingCNAMEs returns the active dangling_cname exposures of
	// source easm_dns on the given assets of the tenant.
	OpenDanglingCNAMEs(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) ([]OpenDangling, error)
	// MarkConfirmed records on the tenant's exposures that a sensor
	// confirmed them (details.confirmation = confirmed, plus evidence).
	MarkConfirmed(ctx context.Context, tenantID shared.ID, exposureIDs []string, evidence map[string]any) error
	ReopenAuto(ctx context.Context, tenantID shared.ID, source string, fingerprints []string, note string) (int, error)
	// AssetNames returns the names of the tenant's assets among ids.
	AssetNames(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]string, error)
}

// TakeoverConfirmer turns sightings into subdomain_takeover exposures.
type TakeoverConfirmer struct {
	store     TakeoverStore
	exposures ExposureUpserter
	dns       Querier
	logger    *logger.Logger
}

// SetResolver lets the confirmer read a sighted name's CNAME chain (DNS only,
// through the platform's configured resolver). Unset, only names with an open
// dangling_cname are confirmed.
func (c *TakeoverConfirmer) SetResolver(q Querier) { c.dns = q }

// NewTakeoverConfirmer creates the confirmer.
func NewTakeoverConfirmer(store TakeoverStore, exposures ExposureUpserter, log *logger.Logger) *TakeoverConfirmer {
	return &TakeoverConfirmer{store: store, exposures: exposures, logger: log.With("service", "easm_takeover")}
}

// IsTakeoverTemplate reports whether a nuclei finding comes from a takeover
// template: tagged "takeover", or a template id naming it (the
// http/takeovers templates are named "<provider>-takeover[-detection]").
func IsTakeoverTemplate(templateID string, tags []string) bool {
	for _, t := range tags {
		if strings.EqualFold(strings.TrimSpace(t), "takeover") {
			return true
		}
	}
	id := strings.ToLower(templateID)
	return strings.HasSuffix(id, "-takeover") || strings.Contains(id, "-takeover-")
}

// ConfirmTakeovers raises subdomain_takeover for every sighting on an asset
// with an open dangling_cname, and marks that dangling_cname confirmed. It
// returns how many takeovers were raised.
func (c *TakeoverConfirmer) ConfirmTakeovers(ctx context.Context, tenantID shared.ID, sightings []TakeoverSighting) (int, error) {
	if c == nil || len(sightings) == 0 || tenantID.IsZero() {
		return 0, nil
	}
	byAsset := map[shared.ID]TakeoverSighting{}
	ids := make([]shared.ID, 0, len(sightings))
	for _, s := range sightings {
		if s.AssetID.IsZero() {
			continue
		}
		if _, ok := byAsset[s.AssetID]; !ok {
			ids = append(ids, s.AssetID)
		}
		byAsset[s.AssetID] = s
	}
	open, err := c.store.OpenDanglingCNAMEs(ctx, tenantID, ids)
	if err != nil {
		return 0, fmt.Errorf("list open dangling CNAMEs: %w", err)
	}
	events := make([]*exposuredom.ExposureEvent, 0, len(open))
	fps := make([]string, 0, len(open))
	hosted, err := c.providerHosted(ctx, tenantID, ids, open, byAsset)
	if err != nil {
		return 0, err
	}
	for _, ev := range hosted {
		events = append(events, ev)
		fps = append(fps, ev.Fingerprint())
	}
	for _, d := range open {
		s, ok := byAsset[d.AssetID]
		if !ok {
			continue
		}
		ev, err := takeoverEvent(tenantID, Target{AssetID: d.AssetID, Name: d.Name}, &d, &s)
		if err != nil {
			return 0, err
		}
		events = append(events, ev)
		fps = append(fps, ev.Fingerprint())
		if err := c.store.MarkConfirmed(ctx, tenantID, []string{d.ExposureID}, map[string]any{
			"confirmed_by_template": s.TemplateID,
			"confirmed_by_sensor":   s.SensorID.String(),
			"takeover_exposure":     ev.Fingerprint(),
		}); err != nil {
			return 0, err
		}
	}
	if len(events) == 0 {
		return 0, nil
	}
	if err := c.exposures.BulkUpsert(ctx, events); err != nil {
		return 0, fmt.Errorf("upsert takeover exposures: %w", err)
	}
	// A takeover the DNS check resolved earlier (the record was fixed, then
	// broke again) is reopened, never one a person resolved.
	if _, err := c.store.ReopenAuto(ctx, tenantID, Source, fps, AutoResolveNote); err != nil {
		return 0, err
	}
	n := 0
	for _, ev := range events {
		if ev.EventType() == exposuredom.EventTypeSubdomainTakeover {
			n++
		}
	}
	c.logger.Info("easm: subdomain takeovers confirmed", "tenant_id", tenantID.String(), "count", n)
	return n, nil
}

// providerHosted builds, for sighted assets with no open dangling_cname, the
// dangling_cname and subdomain_takeover of each name whose CNAME chain ends at
// a listed provider outside the name's own registrable domain.
func (c *TakeoverConfirmer) providerHosted(ctx context.Context, tenantID shared.ID, ids []shared.ID, open []OpenDangling,
	byAsset map[shared.ID]TakeoverSighting,
) ([]*exposuredom.ExposureEvent, error) {
	if c.dns == nil {
		return nil, nil
	}
	hasOpen := make(map[shared.ID]bool, len(open))
	for _, d := range open {
		hasOpen[d.AssetID] = true
	}
	rest := make([]shared.ID, 0, len(ids))
	for _, id := range ids {
		if !hasOpen[id] {
			rest = append(rest, id)
		}
	}
	if len(rest) == 0 {
		return nil, nil
	}
	names, err := c.store.AssetNames(ctx, tenantID, rest)
	if err != nil {
		return nil, fmt.Errorf("read sighted names: %w", err)
	}
	var out []*exposuredom.ExposureEvent
	for _, id := range rest {
		name := names[id]
		if name == "" {
			continue
		}
		a, err := c.dns.Query(ctx, name, dnsprobe.TypeA)
		if err != nil {
			c.logger.Warn("easm: takeover sighting not resolved", "tenant_id", tenantID.String(), "error", err)
			continue
		}
		target := lastCNAME(a)
		if target == "" || registrableDomain(target) == registrableDomain(name) {
			continue
		}
		p, ok := providerFor(target)
		if !ok {
			continue
		}
		t := Target{AssetID: id, Name: name}
		d := Dangling{Outcome: OutcomeDanglingCNAME, Target: target, Chain: cnameChain(a), Addresses: addresses(a), Provider: &p,
			ResponseClass: ClassProviderPage, Severity: exposuredom.SeverityHigh, check: checkSensor,
			Reason: "the name points at " + p.Service + ", which answers with its page for names nobody has claimed"}
		cname, err := danglingEvent(tenantID, t, exposuredom.EventTypeDanglingCNAME, d)
		if err != nil {
			return nil, err
		}
		s := byAsset[id]
		od := OpenDangling{AssetID: id, Name: name, Target: target, Provider: p.Service, ResponseClass: ClassProviderPage}
		take, err := takeoverEvent(tenantID, t, &od, &s)
		if err != nil {
			return nil, err
		}
		out = append(out, cname, take)
	}
	return out, nil
}

// takeoverEvent builds the subdomain_takeover exposure for a name. With a nil
// dangling/sighting it builds the identity only (for the fingerprint the DNS
// check clears when the CNAME is fixed): the title and the domain detail are
// all the fingerprint reads.
func takeoverEvent(tenantID shared.ID, t Target, d *OpenDangling, s *TakeoverSighting) (*exposuredom.ExposureEvent, error) {
	details := map[string]any{keyDomain: t.Name, keyCheck: checkSensor, keyConfirmation: confirmConfirmed}
	if d != nil {
		details["target"] = d.Target
		details["dangling_exposure_id"] = d.ExposureID
		if d.Provider != "" {
			details["provider"] = d.Provider
		}
	}
	if s != nil {
		details["template_id"] = s.TemplateID
		details["sensor_id"] = s.SensorID.String()
		if s.CommandID != nil {
			details["command_id"] = s.CommandID.String()
		}
		if s.Matched != "" {
			details["matched"] = truncate(s.Matched, 500)
		}
	}
	ev, err := exposuredom.NewExposureEvent(tenantID, exposuredom.EventTypeSubdomainTakeover, exposuredom.SeverityHigh,
		"Subdomain takeover: "+t.Name, Source, details)
	if err != nil {
		return nil, err
	}
	target := ""
	if d != nil {
		target = d.Target
	}
	ev.UpdateDescription(fmt.Sprintf("%s points at %s, which is unclaimed, and a sensor takeover check confirmed that it can be claimed. "+
		"Remove the DNS record now, or reclaim the target.", t.Name, target))
	id := t.AssetID
	ev.SetAssetID(&id)
	return ev, nil
}
