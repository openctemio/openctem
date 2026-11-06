// Package contentrule runs detection rules on the platform
// (docs/rfcs/RFC-140-rule-packs.md, docs/architecture/rule-packs.md): it
// builds each organization's engine from the stable platform rule packs and
// the organization's own enabled rules, scans web documents with it, and
// turns secret matches into exposures.
//
// Threat model. Documents are hostile; the engine caps every field and
// budgets every scan. Rules are data: they cannot fetch or send anything,
// and an organization's rules only ever join that organization's engine.
// A matched secret leaves the engine masked (keyed fingerprint, preview,
// length, location) and is never logged.
package contentrule

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	dom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	"github.com/openctemio/openctem/api/pkg/domain/contentrule"
	"github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ExposureSource is the source of the exposures detection rules raise.
const ExposureSource = "detection-rules"

// refreshAfter is how long a built engine is used before the platform
// channels and the organization's rules are read again.
const refreshAfter = time.Minute

// maxCachedTenants bounds the engines kept in memory.
const maxCachedTenants = 512

// PlatformPacks is what the service reads of the platform pack store.
type PlatformPacks interface {
	Channels(ctx context.Context) ([]dom.ChannelPointer, error)
	Archive(ctx context.Context, id string) (*dom.PlatformPack, []byte, error)
}

// ExposureWriter upserts exposures and announces new ones.
type ExposureWriter interface {
	BulkUpsert(ctx context.Context, events []*exposure.ExposureEvent) error
}

// PinRecorder records on a command the rule sets its report was matched
// with.
type PinRecorder interface {
	RecordRulePins(ctx context.Context, tenantID, commandID shared.ID, rules []scanrun.PinnedRules) error
}

type parsedPack struct {
	set contentrule.RuleSet
	ok  bool
}

type tenantEngine struct {
	engine *contentrule.Engine
	key    string
	at     time.Time
}

// Service builds engines and records what they find.
type Service struct {
	platform  PlatformPacks
	org       contentrule.OrganizationRules
	exposures ExposureWriter
	pins      PinRecorder
	fp        *vulnerability.SecretFingerprinter
	log       *slog.Logger
	now       func() time.Time

	mu       sync.Mutex
	packs    map[string]parsedPack // by digest; packs are immutable
	channels []dom.ChannelPointer
	chanAt   time.Time
	engines  map[shared.ID]tenantEngine
}

// NewService builds the service. Every dependency may be nil: without
// platform packs only organization rules run, without an exposure writer
// secrets are not recorded.
func NewService(platform PlatformPacks, org contentrule.OrganizationRules, exposures ExposureWriter, pins PinRecorder,
	fp *vulnerability.SecretFingerprinter, log *slog.Logger,
) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{
		platform: platform, org: org, exposures: exposures, pins: pins, fp: fp, log: log, now: time.Now,
		packs: map[string]parsedPack{}, engines: map[shared.ID]tenantEngine{},
	}
}

// SetOrganizationRules wires the organization rule store.
func (s *Service) SetOrganizationRules(org contentrule.OrganizationRules) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.org = org
	s.engines = map[shared.ID]tenantEngine{}
}

// Invalidate drops a tenant's engine so the next scan rebuilds it (after
// the organization changed its rules).
func (s *Service) Invalidate(tenantID shared.ID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.engines, tenantID)
}

// Fingerprinter keys secret fingerprints for the tenant; nil without a
// server secret.
func (s *Service) Fingerprinter(tenantID shared.ID) contentrule.Fingerprinter {
	if s == nil || s.fp == nil {
		return nil
	}
	fp := s.fp
	return func(v string) string { return fp.Fingerprint(tenantID, v) }
}

// Engine is the tenant's engine: the stable platform rule packs and the
// organization's enabled rules. nil (no error) when there is no rule.
func (s *Service) Engine(ctx context.Context, tenantID shared.ID) (*contentrule.Engine, error) {
	if s == nil || tenantID.IsZero() {
		return nil, nil
	}
	now := s.now()
	s.mu.Lock()
	cached, ok := s.engines[tenantID]
	s.mu.Unlock()
	if ok && now.Sub(cached.at) < refreshAfter {
		return cached.engine, nil
	}
	sets, err := s.platformSets(ctx, now)
	if err != nil {
		return nil, err
	}
	orgSets, err := s.organizationSets(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	sets = append(sets, orgSets...)
	key := setsKey(sets)
	if ok && cached.key == key {
		s.store(tenantID, tenantEngine{engine: cached.engine, key: key, at: now})
		return cached.engine, nil
	}
	engine, errs := contentrule.Compile(sets)
	for _, e := range errs {
		// Platform packs passed lint and organization rules are validated
		// on write, so this is a rule written before a stricter check.
		s.log.Warn("detection rule skipped", "tenant_id", tenantID.String(), "error", logger.SanitizeError(e))
	}
	if engine.Rules() == 0 {
		engine = nil
	}
	s.store(tenantID, tenantEngine{engine: engine, key: key, at: now})
	return engine, nil
}

func (s *Service) store(tenantID shared.ID, te tenantEngine) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.engines) >= maxCachedTenants {
		s.engines = map[shared.ID]tenantEngine{}
	}
	s.engines[tenantID] = te
}

// platformSets reads the stable channels (at most once per refreshAfter)
// and the rule packs they name, parsed once per digest.
func (s *Service) platformSets(ctx context.Context, now time.Time) ([]contentrule.RuleSet, error) {
	if s.platform == nil {
		return nil, nil
	}
	s.mu.Lock()
	chans, fresh := s.channels, now.Sub(s.chanAt) < refreshAfter && s.chanAt != (time.Time{})
	s.mu.Unlock()
	if !fresh {
		all, err := s.platform.Channels(ctx)
		if err != nil {
			return nil, fmt.Errorf("read content channels: %w", err)
		}
		chans = chans[:0:0]
		for _, c := range all {
			if c.Channel == dom.ChannelStable {
				chans = append(chans, c)
			}
		}
		s.mu.Lock()
		s.channels, s.chanAt = chans, now
		s.mu.Unlock()
	}
	var sets []contentrule.RuleSet
	for _, c := range chans {
		p, err := s.pack(ctx, c)
		if err != nil {
			return nil, err
		}
		if p.ok {
			sets = append(sets, p.set)
		}
	}
	sort.Slice(sets, func(i, j int) bool { return sets[i].Origin.Pack < sets[j].Origin.Pack })
	return sets, nil
}

// pack parses the pack a stable channel names; ok is false for a pack of
// another kind. A pack that cannot be read is skipped and logged, never
// fatal for the scan.
func (s *Service) pack(ctx context.Context, c dom.ChannelPointer) (parsedPack, error) {
	s.mu.Lock()
	p, ok := s.packs[c.Digest]
	s.mu.Unlock()
	if ok {
		return p, nil
	}
	meta, data, err := s.platform.Archive(ctx, c.PackID.String())
	if err != nil {
		s.log.Warn("detection rule pack not read", "pack", c.Name, "error", logger.SanitizeError(err))
		return parsedPack{}, nil
	}
	kind := contentrule.Kind(meta.Kind)
	p = parsedPack{}
	if kind.IsValid() {
		arc, err := dom.ReadPlatformCanonical(data, meta.Digest)
		if err != nil {
			s.log.Warn("detection rule pack not read", "pack", c.Name, "error", logger.SanitizeError(err))
			return parsedPack{}, nil
		}
		set := contentrule.RuleSet{Kind: kind, Origin: contentrule.Origin{
			Scope: contentrule.ScopePlatform, Pack: meta.Name, Version: meta.Version, Digest: meta.Digest,
		}}
		for _, f := range arc.Files {
			if !strings.HasSuffix(f.Path, ".yaml") && !strings.HasSuffix(f.Path, ".yml") {
				continue
			}
			rules, err := contentrule.ParseFile(f.Data)
			if err != nil {
				continue // lint refused such a file at ingest
			}
			set.Rules = append(set.Rules, rules...)
		}
		p = parsedPack{set: set, ok: len(set.Rules) > 0}
	}
	s.mu.Lock()
	s.packs[c.Digest] = p
	s.mu.Unlock()
	return p, nil
}

func (s *Service) organizationSets(ctx context.Context, tenantID shared.ID) ([]contentrule.RuleSet, error) {
	s.mu.Lock()
	org := s.org
	s.mu.Unlock()
	if org == nil {
		return nil, nil
	}
	rules, err := org.EnabledRules(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("read organization detection rules: %w", err)
	}
	byKind := map[contentrule.Kind][]contentrule.EnabledRule{}
	for _, r := range rules {
		byKind[r.Kind] = append(byKind[r.Kind], r)
	}
	sets := make([]contentrule.RuleSet, 0, 2)
	for _, k := range []contentrule.Kind{contentrule.KindFingerprint, contentrule.KindSecret} {
		rs := byKind[k]
		if len(rs) == 0 {
			continue
		}
		set := contentrule.RuleSet{Kind: k, Origin: contentrule.Origin{Scope: contentrule.ScopeOrganization, Digest: contentrule.SetDigest(rs)}}
		for _, r := range rs {
			set.Rules = append(set.Rules, r.Rule)
		}
		sets = append(sets, set)
	}
	return sets, nil
}

func setsKey(sets []contentrule.RuleSet) string {
	parts := make([]string, 0, len(sets))
	for _, s := range sets {
		parts = append(parts, string(s.Kind)+"="+s.Origin.Digest)
	}
	return strings.Join(parts, ",")
}

// Pins are the rule sets of an engine as a run record.
func Pins(e *contentrule.Engine) []scanrun.PinnedRules {
	sets := e.Sets()
	out := make([]scanrun.PinnedRules, 0, len(sets))
	for _, s := range sets {
		out = append(out, scanrun.PinnedRules{
			Kind: string(s.Kind), Scope: s.Origin.Scope, Pack: s.Origin.Pack, Version: s.Origin.Version,
			Digest: s.Origin.Digest, Rules: len(s.Rules),
		})
	}
	return out
}

// RecordPins records on a command the rule sets of e. Best effort.
func (s *Service) RecordPins(ctx context.Context, tenantID, commandID shared.ID, e *contentrule.Engine) {
	if s == nil || s.pins == nil || e == nil || commandID.IsZero() {
		return
	}
	if err := s.pins.RecordRulePins(ctx, tenantID, commandID, Pins(e)); err != nil {
		s.log.Warn("detection rule pins not recorded", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
	}
}

// Found is the secrets one document of an asset holds.
type Found struct {
	AssetID shared.ID
	URL     string
	Secrets []contentrule.SecretMatch
}

// RecordSecrets turns secret matches into exposures on their assets, one
// per rule, asset, URL and secret. The caller has checked that the report
// may change each asset.
func (s *Service) RecordSecrets(ctx context.Context, tenantID shared.ID, found []Found) error {
	if s == nil || s.exposures == nil || len(found) == 0 {
		return nil
	}
	var events []*exposure.ExposureEvent
	for _, f := range found {
		for _, m := range f.Secrets {
			ev, err := secretExposure(tenantID, f.AssetID, f.URL, m)
			if err != nil {
				continue
			}
			events = append(events, ev)
		}
	}
	if len(events) == 0 {
		return nil
	}
	if err := s.exposures.BulkUpsert(ctx, events); err != nil {
		return fmt.Errorf("record detection rule exposures: %w", err)
	}
	return nil
}

// secretExposure builds the exposure of one secret match. It carries only
// the masked form; its identity includes the keyed fingerprint (or the
// location without one), so the same secret on the same page is one
// exposure and a rotated one is another.
func secretExposure(tenantID, assetID shared.ID, url string, m contentrule.SecretMatch) (*exposure.ExposureEvent, error) {
	sev, err := exposure.ParseSeverity(m.Severity)
	if err != nil {
		return nil, err
	}
	typ := exposure.EventTypeSensitiveData
	if contentrule.IsCredentialCategory(m.Category) {
		typ = exposure.EventTypeCredentialLeaked
	}
	details := map[string]any{
		"url":                url,
		"rule_id":            m.RuleID,
		"rule_scope":         m.Origin.Scope,
		"field":              m.Field,
		"line":               m.Line,
		"column":             m.Column,
		"secret_kind":        m.Category,
		"secret_masked":      m.Preview,
		"secret_length":      m.Length,
		"secret_fingerprint": m.Fingerprint,
	}
	if m.Origin.Scope == contentrule.ScopePlatform {
		details["pack"], details["pack_version"], details["pack_digest"] = m.Origin.Pack, m.Origin.Version, m.Origin.Digest
	}
	ev, err := exposure.NewExposureEvent(tenantID, typ, sev, m.RuleName, ExposureSource, details)
	if err != nil {
		return nil, err
	}
	id := assetID
	ev.SetAssetID(&id)
	where := m.Fingerprint
	if where == "" {
		where = fmt.Sprintf("%s:%d:%d", m.Field, m.Line, m.Column)
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{tenantID.String(), string(typ), m.RuleID, assetID.String(), url, where}, "\x00")))
	ev.UseFingerprint(hex.EncodeToString(sum[:]))
	return ev, nil
}

// ScanDocument scans one web document of an asset with the tenant's engine
// and records the secrets it holds as exposures. It returns what matched
// (technologies for the caller to record). For a caller that received the
// document's raw content (a page monitoring capture) before it normalizes
// or masks it.
func (s *Service) ScanDocument(ctx context.Context, tenantID, assetID shared.ID, doc contentrule.Document) (contentrule.Result, error) {
	e, err := s.Engine(ctx, tenantID)
	if err != nil || e == nil {
		return contentrule.Result{}, err
	}
	res := e.Scan(ctx, doc, contentrule.DefaultBudget, s.Fingerprinter(tenantID))
	if res.Stopped != "" {
		s.log.Info("detection rule scan stopped by its budget", "tenant_id", tenantID.String(), "budget", res.Stopped,
			"secrets", len(res.Secrets), "technologies", len(res.Technologies))
	}
	if len(res.Secrets) > 0 && !assetID.IsZero() {
		if err := s.RecordSecrets(ctx, tenantID, []Found{{AssetID: assetID, URL: doc.URL, Secrets: res.Secrets}}); err != nil {
			return res, err
		}
	}
	return res, nil
}

// RecordAssetSecrets records the secrets one document of an asset holds.
func (s *Service) RecordAssetSecrets(ctx context.Context, tenantID, assetID shared.ID, url string, secrets []contentrule.SecretMatch) error {
	return s.RecordSecrets(ctx, tenantID, []Found{{AssetID: assetID, URL: url, Secrets: secrets}})
}

// PlatformPacks are the stable platform rule packs every organization's
// engine holds, as run records (name, kind, version, digest, rule count).
func (s *Service) PlatformPacks(ctx context.Context) ([]scanrun.PinnedRules, error) {
	if s == nil {
		return nil, nil
	}
	sets, err := s.platformSets(ctx, s.now())
	if err != nil {
		return nil, err
	}
	out := make([]scanrun.PinnedRules, 0, len(sets))
	for _, set := range sets {
		out = append(out, scanrun.PinnedRules{Kind: string(set.Kind), Scope: set.Origin.Scope, Pack: set.Origin.Pack,
			Version: set.Origin.Version, Digest: set.Origin.Digest, Rules: len(set.Rules)})
	}
	return out, nil
}
