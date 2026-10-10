// Package licensepolicy evaluates the organization's license policy on its
// package links and keeps one license finding per asset, package and
// declared license set that the policy denies (or flags for review, when
// the organization opts in). It runs when the policy changes and after
// every write of an asset's packages (sensor, CI, SBOM import).
//
// Design: api/docs/rfcs/RFC-070-software-components-inventory.md, "License
// policy". Threat model: the policy is configuration of the caller's own
// tenant (settings:write); evaluation reads and writes only that tenant's
// rows; findings are created and closed only under the reserved tool name,
// so the evaluation can never close a finding another producer owns.
package licensepolicy

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/licensepolicy"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/software"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ToolName is the reserved tool name of license findings.
const ToolName = "license-policy"

// LicenseSet is a distinct (declared licenses, dependency scope) pair of the
// tenant's package links.
type LicenseSet struct {
	Licenses []string
	Scope    string
}

// SetVerdict is the verdict of a LicenseSet.
type SetVerdict struct {
	Set     LicenseSet
	Verdict licensepolicy.Verdict
}

// Violation is a package link whose verdict opens a finding.
type Violation struct {
	AssetID   shared.ID
	ProductID shared.ID
	VersionID shared.ID
	PURL      software.PURL
	Version   string
	Licenses  []string
	Verdict   licensepolicy.Verdict
}

// ExistingFinding is a license finding already stored.
type ExistingFinding struct {
	ID               shared.ID
	Fingerprint      string
	Status           string
	Severity         string
	ResolutionMethod string
}

// Store reads and writes the evaluation's rows, always within one tenant
// (and, when assetIDs is not empty, those assets).
type Store interface {
	Catalog(ctx context.Context) (licensepolicy.Catalog, error)
	LicenseSets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) ([]LicenseSet, error)
	SetVerdicts(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, verdicts []SetVerdict) (int64, error)
	ClearVerdicts(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) error
	Violations(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) ([]Violation, error)
	LicenseFindings(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) ([]ExistingFinding, error)
	ResolveFindings(ctx context.Context, tenantID shared.ID, ids []shared.ID) (int, error)
	ReopenFindings(ctx context.Context, tenantID shared.ID, ids []shared.ID) (int, error)
	SetFindingSeverity(ctx context.Context, tenantID shared.ID, ids []shared.ID, severity string) error
}

// FindingCreator stores new findings (the finding repository).
type FindingCreator interface {
	CreateBatchWithResult(ctx context.Context, findings []*vulnerability.Finding) (*vulnerability.BatchCreateResult, error)
}

// TenantReader reads the tenant settings.
type TenantReader interface {
	GetByID(ctx context.Context, id shared.ID) (*tenant.Tenant, error)
}

// Service evaluates license policies.
type Service struct {
	store    Store
	findings FindingCreator
	tenants  TenantReader
	logger   *logger.Logger
}

// NewService creates the service.
func NewService(store Store, findings FindingCreator, tenants TenantReader, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{store: store, findings: findings, tenants: tenants, logger: log}
}

// Result is what an evaluation did.
type Result struct {
	LinksUpdated int64 `json:"links_updated"`
	Violations   int   `json:"violations"`
	Created      int   `json:"findings_created"`
	Reopened     int   `json:"findings_reopened"`
	Resolved     int   `json:"findings_resolved"`
}

// EvaluateTenant re-evaluates every package link of the tenant (after a
// policy change).
func (s *Service) EvaluateTenant(ctx context.Context, tenantID shared.ID) (Result, error) {
	return s.evaluate(ctx, tenantID, nil)
}

// EvaluateAssets re-evaluates the package links of these assets (after a
// write of their packages). Best-effort for the caller.
func (s *Service) EvaluateAssets(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (Result, error) {
	if len(assetIDs) == 0 {
		return Result{}, nil
	}
	return s.evaluate(ctx, tenantID, assetIDs)
}

func (s *Service) policy(ctx context.Context, tenantID shared.ID) (licensepolicy.Policy, error) {
	t, err := s.tenants.GetByID(ctx, tenantID)
	if err != nil {
		return licensepolicy.Policy{}, err
	}
	p := t.TypedSettings().LicensePolicy
	if err := p.Normalize(); err != nil {
		// A stored policy that does not validate evaluates nothing rather
		// than something unintended.
		return licensepolicy.Policy{}, fmt.Errorf("stored license policy: %w", err)
	}
	return p, nil
}

func (s *Service) evaluate(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (Result, error) {
	var res Result
	p, err := s.policy(ctx, tenantID)
	if err != nil {
		return res, err
	}
	var violations []Violation
	if !p.Enabled {
		if err := s.store.ClearVerdicts(ctx, tenantID, assetIDs); err != nil {
			return res, err
		}
	} else {
		cat, err := s.store.Catalog(ctx)
		if err != nil {
			return res, err
		}
		sets, err := s.store.LicenseSets(ctx, tenantID, assetIDs)
		if err != nil {
			return res, err
		}
		verdicts := make([]SetVerdict, len(sets))
		for i, set := range sets {
			verdicts[i] = SetVerdict{Set: set, Verdict: p.Evaluate(set.Licenses, set.Scope, cat)}
		}
		if res.LinksUpdated, err = s.store.SetVerdicts(ctx, tenantID, assetIDs, verdicts); err != nil {
			return res, err
		}
		all, err := s.store.Violations(ctx, tenantID, assetIDs)
		if err != nil {
			return res, err
		}
		for _, v := range all {
			if p.Opens(v.Verdict.Action) {
				violations = append(violations, v)
			}
		}
	}
	res.Violations = len(violations)
	if err := s.reconcileFindings(ctx, tenantID, assetIDs, violations, &res); err != nil {
		return res, err
	}
	return res, nil
}

// desired is a finding the policy wants open.
type desired struct {
	v        Violation
	severity vulnerability.Severity
}

func licenseKey(licenses []string) string {
	l := append([]string(nil), licenses...)
	sort.Strings(l)
	if len(l) == 0 {
		return "NOASSERTION"
	}
	return strings.Join(l, " AND ")
}

// Identity is (asset, package, declared licenses): the installed version
// is not part of a finding's identity (RFC-043), so an upgrade that keeps
// the license keeps the finding.
func identity(v Violation) (vulnerability.IdentityKey, bool) {
	return vulnerability.SCAIdentity(v.AssetID.String(), v.PURL.Base(), "", "", "", "license:"+licenseKey(v.Licenses))
}

func severityFor(a licensepolicy.Action) vulnerability.Severity {
	if a == licensepolicy.ActionDeny {
		return vulnerability.SeverityHigh
	}
	return vulnerability.SeverityMedium
}

func (s *Service) reconcileFindings(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, violations []Violation, res *Result) error {
	want := map[string]desired{}
	order := []string{}
	for _, v := range violations {
		key, ok := identity(v)
		if !ok {
			continue
		}
		fp := key.Fingerprint()
		sev := severityFor(v.Verdict.Action)
		if cur, seen := want[fp]; seen {
			if sev == vulnerability.SeverityHigh && cur.severity != vulnerability.SeverityHigh {
				want[fp] = desired{v: v, severity: sev}
			}
			continue
		}
		want[fp] = desired{v: v, severity: sev}
		order = append(order, fp)
	}
	existing, err := s.store.LicenseFindings(ctx, tenantID, assetIDs)
	if err != nil {
		return err
	}
	have := map[string]ExistingFinding{}
	var resolve, reopen []shared.ID
	bySeverity := map[string][]shared.ID{}
	for _, e := range existing {
		have[e.Fingerprint] = e
		d, wanted := want[e.Fingerprint]
		switch {
		case !wanted:
			if isOpen(e.Status) {
				resolve = append(resolve, e.ID)
			}
		case e.Status == string(vulnerability.FindingStatusResolved) && e.ResolutionMethod == ResolutionMethod:
			reopen = append(reopen, e.ID)
			fallthrough
		default:
			if e.Severity != d.severity.String() {
				bySeverity[d.severity.String()] = append(bySeverity[d.severity.String()], e.ID)
			}
		}
	}
	if res.Resolved, err = s.store.ResolveFindings(ctx, tenantID, resolve); err != nil {
		return err
	}
	if res.Reopened, err = s.store.ReopenFindings(ctx, tenantID, reopen); err != nil {
		return err
	}
	for sev, ids := range bySeverity {
		if err := s.store.SetFindingSeverity(ctx, tenantID, ids, sev); err != nil {
			return err
		}
	}
	create := make([]*vulnerability.Finding, 0, len(order))
	for _, fp := range order {
		if _, ok := have[fp]; ok {
			continue
		}
		f, err := buildFinding(tenantID, want[fp])
		if err != nil {
			s.logger.Warn("license finding not built", "tenant_id", tenantID.String(), "error", err)
			continue
		}
		create = append(create, f)
	}
	if len(create) == 0 {
		return nil
	}
	out, err := s.findings.CreateBatchWithResult(ctx, create)
	if err != nil {
		return err
	}
	res.Created = out.Created
	return nil
}

// ResolutionMethod marks a license finding the policy closed.
const ResolutionMethod = "license_policy"

func isOpen(status string) bool {
	for _, s := range vulnerability.AutoCloseFromStatuses() {
		if string(s) == status {
			return true
		}
	}
	return false
}

func buildFinding(tenantID shared.ID, d desired) (*vulnerability.Finding, error) {
	v := d.v
	name := v.PURL.Name
	if v.PURL.Namespace != "" {
		name = v.PURL.Namespace + "/" + v.PURL.Name
	}
	lic := licenseKey(v.Licenses)
	verb := "denies"
	if v.Verdict.Action == licensepolicy.ActionReview {
		verb = "flags for review"
	}
	f, err := vulnerability.NewFinding(tenantID, v.AssetID, vulnerability.FindingSourceSCA, ToolName, d.severity,
		fmt.Sprintf("%s %s declares %s, which the license policy %s (rule: %s)", name, v.Version, lic, verb, v.Verdict.Rule))
	if err != nil {
		return nil, err
	}
	f.SetTitle(fmt.Sprintf("License %s in %s", lic, name))
	f.SetFindingType(vulnerability.FindingTypeLicense)
	f.SetRuleID("license:" + v.Verdict.Rule)
	f.SetComponentID(v.VersionID)
	key, ok := identity(v)
	if !ok {
		return nil, fmt.Errorf("no identity for the license finding")
	}
	if err := f.SetIdentity(key); err != nil {
		return nil, err
	}
	f.SetMetadata("license_policy", map[string]any{
		"licenses": v.Licenses, "verdict": string(v.Verdict.Action), "rule": v.Verdict.Rule,
		"package": v.PURL.Base(), "version": v.Version, "version_id": v.VersionID.String(),
	})
	return f, nil
}
