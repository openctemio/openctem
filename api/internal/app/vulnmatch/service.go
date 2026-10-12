// Package vulnmatch runs inventory vulnerability matching: it evaluates each
// global catalog version once against its product's ranges, then reconciles
// each organization's findings with the matches of the software it runs.
//
// Design: docs/rfcs/RFC-066-inventory-vulnerability-matching.md (§7, §8, §9).
package vulnmatch

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/softwarematch"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/domain/vulnmatch"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Batch sizes and the time one Run may take.
const (
	versionBatch    = 500
	feedBatch       = 5000
	tenantBatch     = 20
	maxTenantRows   = 100_000
	sweepEvery      = 24 * time.Hour
	stateFeedCursor = "feed_cursor"
	stateLastSweep  = "last_sweep"
)

// PolicyReader returns an organization's vulnerability matching policy.
type PolicyReader interface {
	VulnMatchingPolicy(ctx context.Context, tenantID shared.ID) (tenant.VulnMatchingSettings, error)
}

// FindingWriter persists findings (upsert on the tenant and fingerprint,
// plan limit enforced).
type FindingWriter interface {
	CreateBatchWithResult(ctx context.Context, findings []*vulnerability.Finding) (*vulnerability.BatchCreateResult, error)
}

// Classifier sets EPSS, KEV and the priority class before insert.
type Classifier interface {
	EnrichAndClassifyBatch(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding, assets map[shared.ID]*asset.Asset) error
}

// SLAApplier sets SLA deadlines after classification.
type SLAApplier interface {
	ApplyBatch(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) error
}

// AssetGetter loads an asset for the classifier.
type AssetGetter interface {
	GetByID(ctx context.Context, tenantID, assetID shared.ID) (*asset.Asset, error)
}

// Service is the matcher.
type Service struct {
	store      softwarematch.Store
	policy     PolicyReader
	findings   FindingWriter
	classifier Classifier
	sla        SLAApplier
	assets     AssetGetter
	links      LinkReader
	logger     *logger.Logger
	now        func() time.Time
}

// NewService creates the matcher. classifier, sla and assets are optional.
func NewService(store softwarematch.Store, policy PolicyReader, findings FindingWriter, log *logger.Logger) *Service {
	return &Service{store: store, policy: policy, findings: findings, logger: log, now: time.Now}
}

// SetEnrichment wires the optional pre-insert enrichment.
func (s *Service) SetEnrichment(classifier Classifier, sla SLAApplier, assets AssetGetter) {
	s.classifier, s.sla, s.assets = classifier, sla, assets
}

// SoftwareChanged queues a reconcile of the tenant (ingest's change sink).
func (s *Service) SoftwareChanged(tenantID shared.ID, _ []shared.ID) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.store.QueueTenants(ctx, []shared.ID{tenantID}); err != nil {
		s.logger.Warn("vulnerability matching: tenant not queued", "tenant_id", tenantID.String(), "error", err)
	}
}

// Stats says what a Run did.
type Stats struct {
	VersionsReset     int
	VersionsEvaluated int
	VersionsChanged   int
	Tenants           int
	Created           int
	Reopened          int
	Closed            int
}

// Run does one pass within budget: feed changes reset the affected
// versions, pending versions are evaluated, a daily sweep queues every
// tenant, and queued tenants are reconciled.
func (s *Service) Run(ctx context.Context, budget time.Duration) (Stats, error) {
	var st Stats
	deadline := s.now().Add(budget)
	if err := s.feedDelta(ctx, &st, deadline); err != nil {
		return st, err
	}
	if err := s.evaluate(ctx, &st, deadline); err != nil {
		return st, err
	}
	if err := s.sweep(ctx); err != nil {
		return st, err
	}
	for s.now().Before(deadline) {
		ids, err := s.store.DequeueTenants(ctx, tenantBatch)
		if err != nil {
			return st, err
		}
		if len(ids) == 0 {
			break
		}
		for i, id := range ids {
			if !s.now().Before(deadline) {
				// Out of time: put the rest back.
				if err := s.store.QueueTenants(ctx, ids[i:]); err != nil {
					return st, err
				}
				return st, nil
			}
			if err := s.ReconcileTenant(ctx, id, &st); err != nil {
				s.logger.Warn("vulnerability matching: reconcile failed", "tenant_id", id.String(), "error", err)
				if qerr := s.store.QueueTenants(ctx, []shared.ID{id}); qerr != nil {
					return st, qerr
				}
				continue
			}
			st.Tenants++
		}
	}
	return st, nil
}

func (s *Service) feedDelta(ctx context.Context, st *Stats, deadline time.Time) error {
	cursor, err := s.store.State(ctx, stateFeedCursor)
	if err != nil {
		return err
	}
	for s.now().Before(deadline) {
		next, n, err := s.store.ResetVersionsForCVEsSince(ctx, cursor, feedBatch)
		if err != nil {
			return err
		}
		if !next.After(cursor) {
			return nil
		}
		st.VersionsReset += n
		cursor = next
		if err := s.store.SetState(ctx, stateFeedCursor, cursor); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) evaluate(ctx context.Context, st *Stats, deadline time.Time) error {
	ranges := map[shared.ID][]vulnmatch.Range{}
	for s.now().Before(deadline) {
		versions, err := s.store.PendingVersions(ctx, versionBatch)
		if err != nil {
			return err
		}
		if len(versions) == 0 {
			return nil
		}
		for _, v := range versions {
			rs, ok := ranges[v.ProductID]
			if !ok {
				stored, err := s.store.RangesForProduct(ctx, v.ProductID)
				if err != nil {
					return err
				}
				rs = make([]vulnmatch.Range, len(stored))
				for i, a := range stored {
					rs[i] = a.Range
				}
				ranges[v.ProductID] = rs
			}
			changed, err := s.store.ReplaceVersionVulns(ctx, v.ID, EvaluateVersion(v, rs))
			if err != nil {
				return err
			}
			st.VersionsEvaluated++
			if changed {
				st.VersionsChanged++
			}
		}
	}
	return nil
}

// EvaluateVersion matches one version against its product's ranges.
func EvaluateVersion(v softwarematch.Version, ranges []vulnmatch.Range) []softwarematch.VersionVuln {
	results := vulnmatch.MatchVersion(vulnmatch.Observed{Version: v.Raw, Scheme: v.Scheme, Edition: v.Edition}, ranges)
	out := make([]softwarematch.VersionVuln, 0, len(results))
	for _, r := range results {
		vv := softwarematch.VersionVuln{
			CVEID:       r.VulnID,
			RangeText:   r.Range.Describe(),
			AllVersions: r.AllVersions,
			Adjustment:  r.Adjustment,
			Reasons:     r.Reasons,
		}
		if id, err := strconv.ParseInt(r.Range.ID, 10, 64); err == nil {
			vv.AffectedID = id
		}
		if r.Range.Condition != "" {
			if id, err := shared.IDFromString(r.Range.Condition); err == nil {
				vv.ConditionProductID = &id
			}
		}
		out = append(out, vv)
	}
	return out
}

func (s *Service) sweep(ctx context.Context) error {
	last, err := s.store.State(ctx, stateLastSweep)
	if err != nil {
		return err
	}
	if s.now().Sub(last) < sweepEvery {
		return nil
	}
	if _, err := s.store.QueueAllTenantsWithSoftware(ctx); err != nil {
		return err
	}
	return s.store.SetState(ctx, stateLastSweep, s.now())
}

// candidate is one match that passes the policy.
type candidate struct {
	m          softwarematch.Match
	confidence int
	label      vulnmatch.Label
	reasons    []string
	key        vulnerability.IdentityKey
}

// ReconcileTenant brings one organization's matcher findings in line with
// its current matches and policy (RFC-066 §8).
func (s *Service) ReconcileTenant(ctx context.Context, tenantID shared.ID, st *Stats) error {
	policy, err := s.policy.VulnMatchingPolicy(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	if !policy.Enabled {
		return nil
	}
	currentSince := s.now().Add(-softwarematch.StaleAfter)
	matches, err := s.store.TenantMatches(ctx, tenantID, currentSince, maxTenantRows)
	if err != nil {
		return err
	}
	if len(matches) >= maxTenantRows {
		s.logger.Warn("vulnerability matching: tenant has more matches than one pass reads", "tenant_id", tenantID.String())
	}
	desired, matched := s.plan(tenantID, policy, matches)

	existing, err := s.store.MatcherFindings(ctx, tenantID)
	if err != nil {
		return err
	}
	byFP := make(map[string]softwarematch.MatcherFinding, len(existing))
	for _, f := range existing {
		byFP[f.Fingerprint] = f
	}

	var reopen []shared.ID
	var create []*candidate
	for fp, c := range desired {
		f, ok := byFP[fp]
		switch {
		case !ok:
			create = append(create, c)
		case f.Status == string(vulnerability.FindingStatusResolved) || f.Status == string(vulnerability.FindingStatusNotObserved):
			reopen = append(reopen, f.ID)
		}
	}
	if len(reopen) > 0 {
		done, err := s.store.ReopenFindings(ctx, tenantID, reopen)
		if err != nil {
			return err
		}
		st.Reopened += len(done)
	}
	if err := s.create(ctx, tenantID, create, st); err != nil {
		return err
	}
	return s.close(ctx, tenantID, existing, matched, currentSince, st)
}

// plan scores every match and keeps, per finding identity, the most
// confident one the policy lets through. matched holds the identities that
// still have any findable match, policy or not.
func (s *Service) plan(tenantID shared.ID, policy tenant.VulnMatchingSettings, matches []softwarematch.Match) (map[string]*candidate, map[string]bool) {
	desired := map[string]*candidate{}
	matched := map[string]bool{}
	for _, m := range matches {
		key, ok := vulnerability.NetworkIdentity(m.AssetID.String(), m.Result.CVEID, "", m.Port, m.Transport)
		if !ok {
			continue
		}
		fp := key.Fingerprint()
		res := vulnmatch.Result{VulnID: m.Result.CVEID, AllVersions: m.Result.AllVersions,
			Adjustment: m.Result.Adjustment, Reasons: m.Result.Reasons}
		if m.Result.ConditionProductID != nil {
			res.Range.Condition = m.Result.ConditionProductID.String()
		}
		conf, label, reasons := vulnmatch.Confidence(m.LinkConfidence, res, m.ConditionMet)
		if res.Findable() {
			matched[fp] = true
		}
		if !Passes(policy, m, res, conf) {
			continue
		}
		if prev, ok := desired[fp]; ok && prev.confidence >= conf {
			continue
		}
		desired[fp] = &candidate{m: m, confidence: conf, label: label, reasons: reasons, key: key}
	}
	_ = tenantID
	return desired, matched
}

// Passes applies the organization's policy to one scored match.
func Passes(policy tenant.VulnMatchingSettings, m softwarematch.Match, res vulnmatch.Result, confidence int) bool {
	switch {
	case !res.Findable():
		return false
	case confidence < policy.EffectiveMinConfidence():
		return false
	case m.Qualifier != "" && !policy.IncludeDistroBuilds:
		return false
	case policy.InternetFacingOnly && !m.InternetFacing:
		return false
	case policy.IsMuted(m.Product):
		return false
	}
	return policy.SeverityPasses(m.CVE.Severity) || m.CVE.InKEV || m.CVE.EPSS >= tenant.DefaultVulnMatchMinEPSS
}

func (s *Service) create(ctx context.Context, tenantID shared.ID, cands []*candidate, st *Stats) error {
	if len(cands) == 0 {
		return nil
	}
	assets := make([]shared.ID, 0, len(cands))
	seen := map[shared.ID]bool{}
	for _, c := range cands {
		if !seen[c.m.AssetID] {
			seen[c.m.AssetID] = true
			assets = append(assets, c.m.AssetID)
		}
	}
	open, err := s.store.OpenCVEsOnAssets(ctx, tenantID, assets)
	if err != nil {
		return err
	}
	fps := make([]string, 0, len(cands))
	for _, c := range cands {
		fps = append(fps, c.key.Fingerprint())
	}
	taken, err := s.store.ExistingFingerprints(ctx, tenantID, fps)
	if err != nil {
		return err
	}
	kept := cands[:0]
	cves := make([]softwarematch.CVEInfo, 0, len(cands))
	for _, c := range cands {
		if open[c.m.AssetID][vulnerability.NormalizeCVEID(c.m.Result.CVEID)] {
			continue // a scanner (or a person) already has this CVE open on the asset
		}
		if taken[c.key.Fingerprint()] {
			continue // another tool's finding (open or closed) owns this identity
		}
		kept = append(kept, c)
		cves = append(cves, c.m.CVE)
	}
	if len(kept) == 0 {
		return nil
	}
	defs, err := s.store.EnsureDefinitions(ctx, cves)
	if err != nil {
		return err
	}
	findings := make([]*vulnerability.Finding, 0, len(kept))
	for _, c := range kept {
		f, err := BuildFinding(tenantID, c.m, c.confidence, c.label, c.reasons, c.key)
		if err != nil {
			s.logger.Warn("vulnerability matching: finding not built", "cve", c.m.Result.CVEID, "error", err)
			continue
		}
		if id, ok := defs[c.m.Result.CVEID]; ok {
			f.SetVulnerabilityID(id)
		}
		findings = append(findings, f)
	}
	s.enrich(ctx, tenantID, findings)
	res, err := s.findings.CreateBatchWithResult(ctx, findings)
	if err != nil {
		return err
	}
	if res != nil {
		st.Created += res.Created
		for i, msg := range res.Errors {
			s.logger.Warn("vulnerability matching: finding not stored", "index", i, "error", msg)
		}
	}
	return nil
}

// enrich classifies priority (EPSS, KEV, asset context) and then caps a
// potential match at P2 unless the CVE is known exploited: a banner version
// alone must not make an emergency (RFC-066 §4).
func (s *Service) enrich(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) {
	if s.classifier != nil {
		assets := map[shared.ID]*asset.Asset{}
		if s.assets != nil {
			for _, f := range findings {
				if _, ok := assets[f.AssetID()]; ok {
					continue
				}
				if a, err := s.assets.GetByID(ctx, tenantID, f.AssetID()); err == nil {
					assets[f.AssetID()] = a
				}
			}
		}
		if err := s.classifier.EnrichAndClassifyBatch(ctx, tenantID, findings, assets); err != nil {
			s.logger.Warn("vulnerability matching: priority classification failed", "error", err)
		}
	}
	for _, f := range findings {
		CapPotentialPriority(f)
	}
	if s.sla != nil {
		if err := s.sla.ApplyBatch(ctx, tenantID, findings); err != nil {
			s.logger.Warn("vulnerability matching: sla not applied", "error", err)
		}
	}
}

// CapPotentialPriority lowers a P0/P1 version match below the likely
// threshold to P2 unless the CVE is in KEV.
func CapPotentialPriority(f *vulnerability.Finding) {
	c := f.Confidence()
	if c == nil || *c >= vulnmatch.LikelyThreshold || f.IsInKEV() {
		return
	}
	if p := f.PriorityClass(); p != nil && (*p == vulnerability.PriorityP0 || *p == vulnerability.PriorityP1) {
		f.SetPriorityClassification(vulnerability.PriorityP2,
			"Version-based match below 80% confidence and not known exploited: capped at P2 until a scan or validation confirms it")
	}
}

func (s *Service) close(ctx context.Context, tenantID shared.ID, existing []softwarematch.MatcherFinding,
	matched map[string]bool, currentSince time.Time, st *Stats,
) error {
	var keys []softwarematch.LinkKey
	byKey := map[softwarematch.LinkKey][]shared.ID{}
	for _, f := range existing {
		if matched[f.Fingerprint] || f.CVERejected || f.ProductID == nil || f.VersionID == nil || !isOpen(f.Status) {
			continue
		}
		k := softwarematch.LinkKey{AssetID: f.AssetID, ProductID: *f.ProductID, VersionID: *f.VersionID, Location: f.Location}
		if _, ok := byKey[k]; !ok {
			keys = append(keys, k)
		}
		byKey[k] = append(byKey[k], f.ID)
	}
	if len(keys) == 0 {
		return nil
	}
	states, err := s.store.LinkStates(ctx, tenantID, keys, currentSince)
	if err != nil {
		return err
	}
	toClose := map[softwarematch.CloseKind][]shared.ID{}
	for k, ids := range byKey {
		info := states[k]
		switch {
		case info.State == softwarematch.LinkUpgraded:
			toClose[softwarematch.CloseVersionChanged] = append(toClose[softwarematch.CloseVersionChanged], ids...)
		case info.State == softwarematch.LinkGone:
			toClose[softwarematch.CloseNotObserved] = append(toClose[softwarematch.CloseNotObserved], ids...)
		case info.VersionEvaluated:
			// Same software, evaluated against the current ranges, and the
			// CVE no longer covers it: the advisory changed.
			toClose[softwarematch.CloseAdvisoryUpdated] = append(toClose[softwarematch.CloseAdvisoryUpdated], ids...)
		}
	}
	for kind, ids := range toClose {
		done, err := s.store.CloseFindings(ctx, tenantID, ids, kind)
		if err != nil {
			return err
		}
		st.Closed += len(done)
	}
	return nil
}

func isOpen(status string) bool {
	switch vulnerability.FindingStatus(status) {
	case vulnerability.FindingStatusNew, vulnerability.FindingStatusConfirmed,
		vulnerability.FindingStatusInProgress, vulnerability.FindingStatusFixApplied:
		return true
	}
	return false
}

// TenantGetter loads an organization.
type TenantGetter interface {
	GetByID(ctx context.Context, id shared.ID) (*tenant.Tenant, error)
}

// TenantPolicy reads the policy from the organization's settings.
func TenantPolicy(g TenantGetter) PolicyReader { return tenantPolicy{g} }

type tenantPolicy struct{ g TenantGetter }

func (p tenantPolicy) VulnMatchingPolicy(ctx context.Context, tenantID shared.ID) (tenant.VulnMatchingSettings, error) {
	t, err := p.g.GetByID(ctx, tenantID)
	if err != nil {
		return tenant.VulnMatchingSettings{}, err
	}
	return t.TypedSettings().VulnMatching, nil
}
