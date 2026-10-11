package easm

// Passive lookalike-domain monitoring (docs/rfcs/RFC-083-lookalike-domains.md).
// A watch is one of the organization's root domains (a permanent domain
// scope entry or a verified domain). Its lookalikes are generated locally
// and checked passively only (decision O5): DNS through the platform
// resolver and Certificate Transparency (crt.sh). No candidate host is ever
// contacted. A registered lookalike is a lookalike_domain exposure; one that
// disappears is resolved.

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/dnsprobe"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/lookalike"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// LookalikeSource is the exposure source of lookalike findings.
const LookalikeSource = "easm_lookalike"

// lookalikeGoneNote marks exposures the monitor resolved itself.
const lookalikeGoneNote = "The lookalike domain no longer resolves."

// LookalikeStore stores watches and candidates (*postgres.EASMLookalikeRepository).
type LookalikeStore interface {
	OwnsRoot(ctx context.Context, tenantID shared.ID, domain string) (bool, error)
	ListWatches(ctx context.Context, tenantID shared.ID) ([]lookalike.Watch, error)
	GetWatch(ctx context.Context, tenantID shared.ID, id string) (*lookalike.Watch, error)
	CreateWatch(ctx context.Context, tenantID shared.ID, domain string, techs []lookalike.Technique, maxN int, by *shared.ID) (*lookalike.Watch, error)
	UpdateWatch(ctx context.Context, tenantID shared.ID, id string, enabled bool, techs []lookalike.Technique, maxN int) (*lookalike.Watch, error)
	DeleteWatch(ctx context.Context, tenantID shared.ID, id string) error
	ReplaceCandidates(ctx context.Context, tenantID shared.ID, watchID string, cands []lookalike.Candidate, now time.Time) error
	DueCandidates(ctx context.Context, tenantID shared.ID, watchID string, registeredBefore, otherBefore time.Time, limit int) ([]lookalike.CandidateRecord, error)
	SaveObservation(ctx context.Context, tenantID shared.ID, watchID, domain string, o lookalike.Observation, ctChecked bool, now time.Time) error
	Registered(ctx context.Context, tenantID shared.ID, watchID string, limit int) ([]lookalike.CandidateRecord, error)
	RootAsset(ctx context.Context, tenantID shared.ID, domain string) (*shared.ID, error)
	TenantsWithWatches(ctx context.Context) ([]shared.ID, error)
}

// LookalikeDNS asks the platform resolver (*dnsprobe.Client).
type LookalikeDNS interface {
	Query(ctx context.Context, name string, t dnsprobe.Type) (dnsprobe.Answer, error)
}

// CTCounter counts unexpired certificates CT logs list for a name.
type CTCounter interface {
	CountCerts(ctx context.Context, domain string) (int, error)
}

// LookalikeExposures writes and resolves the exposures.
type LookalikeExposures interface {
	BulkUpsert(ctx context.Context, events []*exposuredom.ExposureEvent) error
}

// LookalikeResolver resolves exposures the monitor found gone
// (*postgres.EASMDNSRepository).
type LookalikeResolver interface {
	ResolveAuto(ctx context.Context, tenantID shared.ID, source string, fingerprints []string, note string) (int, error)
}

// Budgets of one run.
const (
	lookalikeChecksPerWatch  = 100
	lookalikeChecksPerTenant = 300
	lookalikeCTPerTenant     = 10
	lookalikeRegisteredEvery = 24 * time.Hour
	lookalikeOtherEvery      = 7 * 24 * time.Hour
	lookalikeCTEvery         = 7 * 24 * time.Hour
	lookalikeListLimit       = 200
)

// LookalikeService manages watches and runs the passive checks.
type LookalikeService struct {
	store     LookalikeStore
	dns       LookalikeDNS
	ct        CTCounter
	exposures LookalikeExposures
	resolver  LookalikeResolver
	log       *logger.Logger
	now       func() time.Time
}

// NewLookalikeService creates the service. dns, ct, exposures and resolver
// may be nil (checks skipped).
func NewLookalikeService(store LookalikeStore, dns LookalikeDNS, ct CTCounter, exposures LookalikeExposures, resolver LookalikeResolver, log *logger.Logger) *LookalikeService {
	if log == nil {
		log = logger.NewNop()
	}
	return &LookalikeService{store: store, dns: dns, ct: ct, exposures: exposures, resolver: resolver, log: log,
		now: func() time.Time { return time.Now().UTC() }}
}

// ErrNotOwnRoot refuses a watch on a domain that is not the organization's.
var ErrNotOwnRoot = fmt.Errorf("%w: watch one of your root domains: a permanent domain scope entry or a verified domain", shared.ErrValidation)

func normalizeWatchSettings(techs []string, maxN int) ([]lookalike.Technique, int, error) {
	out := make([]lookalike.Technique, 0, len(techs))
	seen := map[lookalike.Technique]bool{}
	for _, s := range techs {
		t := lookalike.Technique(s)
		if !t.IsValid() {
			return nil, 0, fmt.Errorf("%w: unknown technique %q", shared.ErrValidation, s)
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	if maxN == 0 {
		maxN = lookalike.DefaultMaxCandidates
	}
	if maxN < 10 || maxN > lookalike.MaxCandidates {
		return nil, 0, fmt.Errorf("%w: max_candidates must be between 10 and %d", shared.ErrValidation, lookalike.MaxCandidates)
	}
	return out, maxN, nil
}

// ListWatches returns the organization's watches.
func (s *LookalikeService) ListWatches(ctx context.Context, tenantID shared.ID) ([]lookalike.Watch, error) {
	return s.store.ListWatches(ctx, tenantID)
}

// CreateWatch watches one of the organization's root domains and generates
// its candidates.
func (s *LookalikeService) CreateWatch(ctx context.Context, tenantID shared.ID, actor *shared.ID, domain string, techs []string, maxN int) (*lookalike.Watch, error) {
	root, err := lookalike.RootDomain(domain)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", shared.ErrValidation, err)
	}
	ts, maxN, err := normalizeWatchSettings(techs, maxN)
	if err != nil {
		return nil, err
	}
	own, err := s.store.OwnsRoot(ctx, tenantID, root)
	if err != nil {
		return nil, err
	}
	if !own {
		return nil, ErrNotOwnRoot
	}
	w, err := s.store.CreateWatch(ctx, tenantID, root, ts, maxN, actor)
	if err != nil {
		return nil, err
	}
	if err := s.generate(ctx, tenantID, w); err != nil {
		s.log.Warn("lookalike candidates not generated", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
	}
	return s.store.GetWatch(ctx, tenantID, w.ID)
}

// UpdateWatch changes a watch's settings.
func (s *LookalikeService) UpdateWatch(ctx context.Context, tenantID shared.ID, id string, enabled bool, techs []string, maxN int) (*lookalike.Watch, error) {
	ts, maxN, err := normalizeWatchSettings(techs, maxN)
	if err != nil {
		return nil, err
	}
	w, err := s.store.UpdateWatch(ctx, tenantID, id, enabled, ts, maxN)
	if err != nil {
		return nil, err
	}
	if w.GeneratedAt == nil {
		if err := s.generate(ctx, tenantID, w); err != nil {
			s.log.Warn("lookalike candidates not generated", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		}
		return s.store.GetWatch(ctx, tenantID, id)
	}
	return w, nil
}

// DeleteWatch stops watching a domain; its open lookalike exposures are
// resolved.
func (s *LookalikeService) DeleteWatch(ctx context.Context, tenantID shared.ID, id string) error {
	reg, err := s.store.Registered(ctx, tenantID, id, lookalike.MaxCandidates)
	if err != nil {
		return err
	}
	if err := s.store.DeleteWatch(ctx, tenantID, id); err != nil {
		return err
	}
	if s.resolver != nil && len(reg) > 0 {
		fps := make([]string, 0, len(reg))
		for _, c := range reg {
			fps = append(fps, lookalikeFingerprint(tenantID, c.Domain))
		}
		if _, err := s.resolver.ResolveAuto(ctx, tenantID, LookalikeSource, fps, "The domain is no longer watched for lookalikes."); err != nil {
			s.log.Warn("lookalike exposures not resolved", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		}
	}
	return nil
}

// Registered returns a watch's registered lookalikes.
func (s *LookalikeService) Registered(ctx context.Context, tenantID shared.ID, id string) ([]lookalike.CandidateRecord, error) {
	if _, err := s.store.GetWatch(ctx, tenantID, id); err != nil {
		return nil, err
	}
	return s.store.Registered(ctx, tenantID, id, lookalikeListLimit)
}

func (s *LookalikeService) generate(ctx context.Context, tenantID shared.ID, w *lookalike.Watch) error {
	cands := lookalike.Generate(w.Domain, w.Techniques, w.MaxCandidates)
	return s.store.ReplaceCandidates(ctx, tenantID, w.ID, cands, s.now())
}

// Run checks every tenant with an enabled watch; skip says no to tenants
// whose module is off. Returns how many candidates were checked.
func (s *LookalikeService) Run(ctx context.Context, skip func(shared.ID) bool) (int, error) {
	if s.dns == nil {
		return 0, nil
	}
	tenants, err := s.store.TenantsWithWatches(ctx)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, t := range tenants {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		if skip != nil && skip(t) {
			continue
		}
		n, err := s.RunTenant(ctx, t)
		if err != nil {
			s.log.Warn("lookalike checks failed; continuing", "tenant_id", t.String(), "error", logger.SanitizeError(err))
		}
		total += n
	}
	return total, nil
}

// RunTenant checks the due candidates of one tenant's enabled watches.
func (s *LookalikeService) RunTenant(ctx context.Context, tenantID shared.ID) (int, error) {
	watches, err := s.store.ListWatches(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	checked, ctBudget := 0, lookalikeCTPerTenant
	for i := range watches {
		w := &watches[i]
		if !w.Enabled || checked >= lookalikeChecksPerTenant {
			continue
		}
		if w.GeneratedAt == nil {
			if err := s.generate(ctx, tenantID, w); err != nil {
				return checked, err
			}
		}
		now := s.now()
		limit := min(lookalikeChecksPerWatch, lookalikeChecksPerTenant-checked)
		due, err := s.store.DueCandidates(ctx, tenantID, w.ID, now.Add(-lookalikeRegisteredEvery), now.Add(-lookalikeOtherEvery), limit)
		if err != nil {
			return checked, err
		}
		n, err := s.checkWatch(ctx, tenantID, w, due, &ctBudget)
		checked += n
		if err != nil {
			return checked, err
		}
	}
	return checked, nil
}

func (s *LookalikeService) checkWatch(ctx context.Context, tenantID shared.ID, w *lookalike.Watch, due []lookalike.CandidateRecord, ctBudget *int) (int, error) {
	root, err := s.store.RootAsset(ctx, tenantID, w.Domain)
	if err != nil {
		return 0, err
	}
	var events []*exposuredom.ExposureEvent
	var gone []string
	checked := 0
	for _, c := range due {
		if err := ctx.Err(); err != nil {
			break
		}
		o := s.observe(ctx, c.Domain)
		if o.Unknown {
			continue
		}
		ctChecked := false
		if o.Registered && s.ct != nil && *ctBudget > 0 && (c.CTCheckedAt == nil || s.now().Sub(*c.CTCheckedAt) > lookalikeCTEvery) {
			*ctBudget--
			if n, err := s.ct.CountCerts(ctx, c.Domain); err == nil {
				o.CTCerts, ctChecked = n, true
			}
		} else {
			o.CTCerts = c.CTCerts
		}
		if err := s.store.SaveObservation(ctx, tenantID, w.ID, c.Domain, o, ctChecked, s.now()); err != nil {
			return checked, err
		}
		checked++
		switch {
		case o.Registered:
			ev, err := lookalikeExposure(tenantID, root, w.Domain, c, o)
			if err != nil {
				return checked, err
			}
			events = append(events, ev)
		case c.State == "registered":
			gone = append(gone, lookalikeFingerprint(tenantID, c.Domain))
		}
	}
	if s.exposures != nil && len(events) > 0 {
		if err := s.exposures.BulkUpsert(ctx, events); err != nil {
			return checked, fmt.Errorf("lookalike exposures: %w", err)
		}
	}
	if s.resolver != nil && len(gone) > 0 {
		if _, err := s.resolver.ResolveAuto(ctx, tenantID, LookalikeSource, gone, lookalikeGoneNote); err != nil {
			return checked, fmt.Errorf("resolve gone lookalikes: %w", err)
		}
	}
	return checked, nil
}

// observe asks the resolver about the candidate: NS (exists?), then A and MX.
func (s *LookalikeService) observe(ctx context.Context, domain string) lookalike.Observation {
	ns, err := s.dns.Query(ctx, domain, dnsprobe.TypeNS)
	if err != nil {
		return lookalike.Observation{Unknown: true}
	}
	switch ns.RCode {
	case dnsprobe.RCodeNXDomain:
		return lookalike.Observation{}
	case dnsprobe.RCodeSuccess:
	default:
		return lookalike.Observation{Unknown: true}
	}
	o := lookalike.Observation{Registered: true}
	for _, r := range append(ns.Records, ns.Authority...) {
		if r.Type == dnsprobe.TypeNS && len(o.NS) < 13 {
			o.NS = append(o.NS, r.Value)
		}
	}
	if a, err := s.dns.Query(ctx, domain, dnsprobe.TypeA); err == nil && a.RCode == dnsprobe.RCodeSuccess {
		o.HasA = a.Has(dnsprobe.TypeA)
	}
	if !o.HasA {
		if a, err := s.dns.Query(ctx, domain, dnsprobe.TypeAAAA); err == nil && a.RCode == dnsprobe.RCodeSuccess {
			o.HasA = a.Has(dnsprobe.TypeAAAA)
		}
	}
	if mx, err := s.dns.Query(ctx, domain, dnsprobe.TypeMX); err == nil && mx.RCode == dnsprobe.RCodeSuccess {
		o.HasMX = mx.Has(dnsprobe.TypeMX)
	}
	return o
}

func lookalikeFingerprint(tenantID shared.ID, domain string) string {
	return exposuredom.Fingerprint(tenantID.String(), string(exposuredom.EventTypeLookalikeDomain), "lookalike", LookalikeSource, "",
		map[string]any{"domain": domain})
}

func lookalikeExposure(tenantID shared.ID, root *shared.ID, watched string, c lookalike.CandidateRecord, o lookalike.Observation) (*exposuredom.ExposureEvent, error) {
	sev, err := exposuredom.ParseSeverity(o.Severity())
	if err != nil {
		return nil, err
	}
	display := lookalike.Display(c.Domain)
	ev, err := exposuredom.NewExposureEvent(tenantID, exposuredom.EventTypeLookalikeDomain, sev,
		"Lookalike domain registered: "+display, LookalikeSource, map[string]any{
			"domain": c.Domain, "display": display, "lookalike_of": watched, "technique": c.Technique,
			"has_a": o.HasA, "has_mx": o.HasMX, "name_servers": o.NS, "ct_certificates": o.CTCerts,
		})
	if err != nil {
		return nil, err
	}
	if root != nil {
		ev.SetAssetID(root)
	}
	ev.UseFingerprint(lookalikeFingerprint(tenantID, c.Domain))
	return ev, nil
}
