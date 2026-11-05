// Package easmdns runs EASM's DNS-only checks (RFC-036 P1) for each tenant:
// dangling DNS (a CNAME or delegation pointing at something that does not
// exist — the subdomain-takeover precondition) and, in email.go, email
// security posture. They are passive (tier T0): the platform asks its
// configured recursive resolver about the tenant's own names and never sends a
// packet to the tenant's hosts or to the CNAME targets.
//
// Which names: the tenant's active domain and subdomain assets whose
// attribution is not "rejected". A name awaiting review is still checked: a
// DNS lookup of a name is passive, and a dangling record under the tenant's
// domain is worth knowing before anyone has confirmed the host.
//
// Each run picks the names checked longest ago first, up to a per-run cap
// (the asset coverage ledger), so a large inventory is covered over several runs
// and a restart does not re-check everything. Findings become exposure events
// (dangling_cname, dangling_ns, email_security_weak); a later check that finds
// the problem gone resolves the exposure, and one that finds it back reopens
// it — but only exposures this check resolved itself, never one a person
// resolved or accepted.
package easmdns

import (
	"context"
	"fmt"
	"strings"
	"time"

	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Source is the exposure source tag for everything these checks emit.
const Source = "easm_dns"

// AutoResolveNote marks exposures this package resolved, so it only ever
// reopens its own resolutions.
const AutoResolveNote = "Resolved automatically: the DNS check no longer finds the problem."

// Check kinds; the ledger capability of a kind is "dns.<kind>".
const (
	KindDangling = "dangling"
	KindEmail    = "email"
)

// Defaults.
const (
	DefaultMaxNamesPerRun = 2000
	DefaultRecheckAfter   = 20 * time.Hour
	DefaultSweepBudget    = 30 * time.Minute
)

// Target is one asset to check.
type Target struct {
	AssetID shared.ID
	Name    string
}

// Store is the persistence the checks need. Satisfied by
// *postgres.EASMDNSRepository.
type Store interface {
	DueTargets(ctx context.Context, tenantID shared.ID, kind string, checkedBefore time.Time, limit int) ([]Target, error)
	SaveState(ctx context.Context, tenantID, assetID shared.ID, kind, outcome, lastErr string, at time.Time) error
	// SaveNameState records the outcome for a name target (a root-domain
	// scope entry with discovery or verified domain with no domain asset; email check only).
	SaveNameState(ctx context.Context, tenantID shared.ID, name, kind, outcome, lastErr string, at time.Time) error
	ResolveAuto(ctx context.Context, tenantID shared.ID, source string, fingerprints []string, note string) (int, error)
	ReopenAuto(ctx context.Context, tenantID shared.ID, source string, fingerprints []string, note string) (int, error)
	TryLockTenant(ctx context.Context, tenantID shared.ID, kind string) (func(), bool, error)
	LifecycleStore
}

// ExposureUpserter writes exposure events (fingerprint-deduped).
type ExposureUpserter interface {
	BulkUpsert(ctx context.Context, events []*exposuredom.ExposureEvent) error
}

// Service runs the checks.
type Service struct {
	dns       Querier
	store     Store
	exposures ExposureUpserter
	logger    *logger.Logger

	maxNames     int
	recheckAfter time.Duration
	sweepBudget  time.Duration
	// tenantSettings carries the per-tenant switch and interval.
	tenantSettings TenantSettingsReader
	now            func() time.Time
}

// NewService builds the checks.
func NewService(dns Querier, store Store, exposures ExposureUpserter, log *logger.Logger) *Service {
	return &Service{
		dns: dns, store: store, exposures: exposures,
		logger:       log.With("service", "easm_dns"),
		maxNames:     DefaultMaxNamesPerRun,
		recheckAfter: DefaultRecheckAfter,
		sweepBudget:  DefaultSweepBudget,
		now:          func() time.Time { return time.Now().UTC() },
	}
}

// SetLimits overrides the per-run cap and re-check age (zero keeps defaults).
func (s *Service) SetLimits(maxNames int, recheckAfter time.Duration) {
	if maxNames > 0 {
		s.maxNames = maxNames
	}
	if recheckAfter > 0 {
		s.recheckAfter = recheckAfter
	}
}

// RunResult counts what one tenant run did.
type RunResult struct {
	Checked, Found, Resolved, Reopened, Unknown int
}

// MonitorTenant runs the dangling-DNS check for one tenant.
func (s *Service) MonitorTenant(ctx context.Context, tenantID shared.ID) (RunResult, error) {
	return s.run(ctx, tenantID, KindDangling, s.checkDanglingTarget)
}

// checkFunc checks one target. found are the events to raise; clear are the
// fingerprints of events that must not be open for this target any more.
type checkFunc func(ctx context.Context, tenantID shared.ID, t Target) (outcome string, found []*exposuredom.ExposureEvent, clear []string, err error)

func (s *Service) run(ctx context.Context, tenantID shared.ID, kind string, check checkFunc) (RunResult, error) {
	var res RunResult
	if s == nil || s.dns == nil || s.store == nil || s.exposures == nil {
		return res, nil
	}
	if tenantID.IsZero() {
		return res, fmt.Errorf("%w: tenant ID is required", shared.ErrValidation)
	}
	release, ok, err := s.store.TryLockTenant(ctx, tenantID, kind)
	if err != nil {
		return res, err
	}
	if !ok {
		s.logger.Info("easm dns: another instance is checking this tenant; skipping", "tenant_id", tenantID.String(), "check", kind)
		return res, nil
	}
	defer release()

	run, recheck := s.tenantRecheck(ctx, tenantID)
	if !run {
		return res, nil
	}
	started := s.now()
	targets, err := s.store.DueTargets(ctx, tenantID, kind, started.Add(-recheck), s.maxNames)
	if err != nil {
		return res, fmt.Errorf("list %s targets: %w", kind, err)
	}

	var raise []*exposuredom.ExposureEvent
	var raisedFPs, clearFPs []string
	for _, t := range targets {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if s.now().Sub(started) > s.sweepBudget {
			s.logger.Warn("easm dns: time budget spent; the rest go first next run",
				"tenant_id", tenantID.String(), "check", kind)
			break
		}
		outcome, found, clear, err := check(ctx, tenantID, t)
		res.Checked++
		errText := ""
		if err != nil {
			errText = truncate(err.Error(), 300)
		}
		if outcome == OutcomeUnknown {
			// Nothing concluded: neither raise nor resolve.
			res.Unknown++
		} else {
			for _, ev := range found {
				raise = append(raise, ev)
				raisedFPs = append(raisedFPs, ev.Fingerprint())
			}
			clearFPs = append(clearFPs, clear...)
		}
		var saveErr error
		if t.AssetID.IsZero() {
			saveErr = s.store.SaveNameState(ctx, tenantID, t.Name, kind, outcome, errText, s.now())
		} else {
			saveErr = s.store.SaveState(ctx, tenantID, t.AssetID, kind, outcome, errText, s.now())
		}
		if err := saveErr; err != nil {
			s.logger.Warn("easm dns: failed to save state", "tenant_id", tenantID.String(), "error", err)
		}
	}

	if len(raise) > 0 {
		if err := s.exposures.BulkUpsert(ctx, raise); err != nil {
			return res, fmt.Errorf("upsert %s exposures: %w", kind, err)
		}
		res.Found = len(raise)
		n, err := s.store.ReopenAuto(ctx, tenantID, Source, raisedFPs, AutoResolveNote)
		if err != nil {
			return res, err
		}
		res.Reopened = n
	}
	if len(clearFPs) > 0 {
		n, err := s.store.ResolveAuto(ctx, tenantID, Source, clearFPs, AutoResolveNote)
		if err != nil {
			return res, err
		}
		res.Resolved = n
	}
	s.logger.Info("easm dns check complete", "tenant_id", tenantID.String(), "check", kind,
		"checked", res.Checked, "found", res.Found, "resolved", res.Resolved, "reopened", res.Reopened, "unknown", res.Unknown)
	return res, nil
}

func (s *Service) checkDanglingTarget(ctx context.Context, tenantID shared.ID, t Target) (string, []*exposuredom.ExposureEvent, []string, error) {
	d, err := checkDangling(ctx, s.dns, t.Name)
	if err != nil || d.Outcome == OutcomeUnknown {
		return OutcomeUnknown, nil, nil, err
	}
	if d.Outcome == OutcomeDanglingCNAME {
		d.ResponseClass = ClassNXDomainTarget
	}
	cname, err := danglingEvent(tenantID, t, exposuredom.EventTypeDanglingCNAME, d)
	if err != nil {
		return OutcomeUnknown, nil, nil, err
	}
	ns, err := danglingEvent(tenantID, t, exposuredom.EventTypeDanglingNS, d)
	if err != nil {
		return OutcomeUnknown, nil, nil, err
	}
	// A confirmed takeover of this name stays open while the CNAME dangles,
	// and is resolved with it once the name points into the organization.
	takeover, err := takeoverEvent(tenantID, t, nil, nil)
	if err != nil {
		return OutcomeUnknown, nil, nil, err
	}
	switch d.Outcome {
	case OutcomeDanglingCNAME:
		s.tag(ctx, tenantID, t, true)
		return d.Outcome, []*exposuredom.ExposureEvent{cname}, []string{ns.Fingerprint()}, nil
	case OutcomeDanglingNS:
		return d.Outcome, []*exposuredom.ExposureEvent{ns}, []string{cname.Fingerprint(), takeover.Fingerprint()}, nil
	}
	return s.checkResolvingName(ctx, tenantID, t, d, cname, ns, takeover)
}

// checkResolvingName handles a name whose answer is ok: it resolves, or
// points nowhere. See lifecycle.go for the rules.
func (s *Service) checkResolvingName(ctx context.Context, tenantID shared.ID, t Target, d Dangling,
	cname, ns, takeover *exposuredom.ExposureEvent,
) (string, []*exposuredom.ExposureEvent, []string, error) {
	everything := []string{cname.Fingerprint(), ns.Fingerprint(), takeover.Fingerprint()}
	if t.AssetID.IsZero() {
		return OutcomeOK, nil, everything, nil
	}
	owned, err := s.ownedResolution(ctx, tenantID, t.Name, d)
	if err != nil {
		return OutcomeUnknown, nil, nil, err
	}
	if owned {
		s.tag(ctx, tenantID, t, false)
		return OutcomeOK, nil, everything, nil
	}
	// A third party answers for the name.
	open, err := s.store.OpenDanglingCNAMEs(ctx, tenantID, []shared.ID{t.AssetID})
	if err != nil {
		return OutcomeUnknown, nil, nil, err
	}
	var trouble []CertTrouble
	if d.Provider != nil {
		if trouble, err = s.store.HostCertificateTrouble(ctx, tenantID, t.Name); err != nil {
			return OutcomeUnknown, nil, nil, err
		}
	}
	var raise []*exposuredom.ExposureEvent
	keepDangling := false
	for _, o := range open {
		switch {
		case o.ResponseClass == "" || o.ResponseClass == ClassNXDomainTarget || !sameTarget(o.Target, d.Target):
			// The target that did not exist now answers, or the name moved
			// to another third party: what a takeover looks like.
			ev, err := suspectedTakeoverEvent(tenantID, t, o, d)
			if err != nil {
				return OutcomeUnknown, nil, nil, err
			}
			raise = append(raise, ev)
			keepDangling = true
		case o.ResponseClass == ClassProviderRefuses && len(trouble) == 0:
			// The provider serves the name a valid certificate again.
		default:
			keepDangling = true
		}
	}
	if d.Provider != nil && len(trouble) > 0 && !keepDangling {
		ev, err := providerRefusesEvent(tenantID, t, d, trouble)
		if err != nil {
			return OutcomeUnknown, nil, nil, err
		}
		raise = append(raise, ev)
		keepDangling = true
	}
	clear := []string{ns.Fingerprint()}
	if !keepDangling {
		clear = append(clear, cname.Fingerprint())
	}
	s.tag(ctx, tenantID, t, keepDangling)
	if keepDangling {
		return OutcomeDanglingCNAME, raise, clear, nil
	}
	return OutcomeOK, raise, clear, nil
}

// tag keeps the dangling tag in step with the outcome. Best effort: the tag
// is for people, decisions read the exposures.
func (s *Service) tag(ctx context.Context, tenantID shared.ID, t Target, on bool) {
	if t.AssetID.IsZero() {
		return
	}
	if err := s.store.SetDanglingTag(ctx, tenantID, t.AssetID, on); err != nil {
		s.logger.Warn("easm dns: failed to update the dangling tag", "tenant_id", tenantID.String(), "error", err)
	}
}

// danglingEvent builds the exposure for one name. The title carries only the
// name, so the fingerprint stays the same when the record changes target and
// a fixed-then-broken-again record reopens the same exposure.
func danglingEvent(tenantID shared.ID, t Target, typ exposuredom.EventType, d Dangling) (*exposuredom.ExposureEvent, error) {
	title := "Dangling CNAME: " + t.Name
	if typ == exposuredom.EventTypeDanglingNS {
		title = "Dangling delegation: " + t.Name
	}
	sev := d.Severity
	if sev == "" {
		sev = exposuredom.SeverityLow
	}
	details := map[string]any{
		keyDomain:      t.Name,
		"target":       d.Target,
		"unregistered": d.Unregistered,
		"reason":       d.Reason,
		keyCheck:       "dns_only",
		"cname_chain":  d.Chain,
		// A sensor takeover check (nuclei "takeover", T1) is what confirms
		// it; until then this is a candidate (RFC-036 P1).
		"confirmation": "pending",
	}
	if d.check == checkSensor {
		details[keyConfirmation] = confirmConfirmed
	}
	if d.Provider != nil {
		details["provider"] = d.Provider.Service
		details["provider_status"] = d.Provider.Status
		details["provider_claimable"] = claimability(d.Provider)
	}
	if d.ResponseClass != "" {
		details["response_class"] = d.ResponseClass
	}
	if d.check != "" {
		details[keyCheck] = d.check
	}
	if len(d.tlsState) > 0 {
		details["tls_state"] = d.tlsState
	}
	if len(d.Missing) > 0 {
		details["missing_name_servers"] = d.Missing
		details["name_servers_total"] = d.Total
	}
	if len(d.Lame) > 0 {
		details["lame_name_servers"] = d.Lame
		details["name_servers_total"] = d.Total
	}
	ev, err := exposuredom.NewExposureEvent(tenantID, typ, sev, title, Source, details)
	if err != nil {
		return nil, err
	}
	desc := fmt.Sprintf("%s: %s (%s). Remove the record if the service is gone, or reclaim the target.", t.Name, d.Reason, d.Target)
	if typ == exposuredom.EventTypeDanglingNS {
		desc = fmt.Sprintf("%s is delegated to name servers that do not exist (%s): %s. Remove the delegation or fix the name servers.",
			t.Name, strings.Join(d.Missing, ", "), d.Reason)
		if len(d.Lame) > 0 {
			desc = fmt.Sprintf("%s is delegated to name servers that do not serve the zone (%s): %s. Remove the delegation or recreate the zone at the provider.",
				t.Name, strings.Join(append(append([]string{}, d.Missing...), d.Lame...), ", "), d.Reason)
		}
	}
	ev.UpdateDescription(desc)
	id := t.AssetID
	ev.SetAssetID(&id)
	return ev, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
