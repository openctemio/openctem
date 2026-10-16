package scan

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// Quick Scan preview: for each target typed into the Quick Scan dialog, what a
// run would do with it, computed by the code the run uses (resolveScanTargets:
// selector expansion, then the one dispatch gate), for the caller as the
// actor. Read-only: no scan, run or command is created.
//
// Security: tenant-scoped (the inventory read and the gate are pinned to the
// tenant), the caller's data scope applies (the gate's act-scope check runs
// as the caller), free text no scope entry covers is rejected before it is
// resolved, and the output is bounded (maxQuickPreviewTargets targets,
// quickPreviewSampleSize names each).

const (
	// maxQuickPreviewTargets bounds how many typed targets one preview
	// resolves; the rest are only counted.
	maxQuickPreviewTargets = 20
	// quickPreviewSampleSize bounds the names shown per target.
	quickPreviewSampleSize = 5
	// maxQuickPreviewRules bounds the exclusion rules named per target.
	maxQuickPreviewRules = 5
)

// Reasons a name is left out of a run, as the preview reports them.
const (
	SkipExcluded         = "excluded"
	SkipOutOfScope       = "out_of_scope"
	SkipNotConfirmed     = "ownership_unconfirmed"
	SkipTierExceeded     = "tier_exceeded"
	SkipInternalNoZone   = "internal_outside_zones"
	SkipIncompatibleType = "incompatible_type"
	SkipArchived         = "archived"
)

// Kinds of a typed target, and the codes of a refused one.
const (
	QuickKindHost     = "host"
	QuickKindWildcard = SelectorKindWildcard
	QuickKindCIDR     = SelectorKindCIDR

	QuickRefusedInvalid    = "invalid_target"
	QuickRefusedNotAllowed = "not_allowed"
	QuickRefusedRun        = "run_refused"
)

// QuickScanPreviewInput is what the Quick Scan dialog would start.
type QuickScanPreviewInput struct {
	TenantID    string
	UserID      string
	Targets     []string
	ScannerName string
	WorkflowID  string
}

// QuickPreviewSkip is a count of names left out, with the reason.
type QuickPreviewSkip struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

// QuickPreviewDiscovery offers subdomain discovery on an apex when a wildcard
// matches no known name.
type QuickPreviewDiscovery struct {
	Tool string `json:"tool"`
	Root string `json:"root"`
}

// QuickPreviewTarget is what one typed target becomes.
type QuickPreviewTarget struct {
	Target string `json:"target"`
	Kind   string `json:"kind"` // host | wildcard | cidr
	// Known is the number of inventory assets a wildcard or inventory-mode
	// range covers (at most the selector cap; Capped when more exist).
	Known  int  `json:"known"`
	Capped bool `json:"capped,omitempty"`
	// InScope is how many names the run would dispatch for the target.
	InScope int `json:"in_scope"`
	// Skipped are the names the run leaves out, by reason.
	Skipped []QuickPreviewSkip `json:"skipped,omitempty"`
	// ExcludedRules names the exclusion rules behind SkipExcluded.
	ExcludedRules []string `json:"excluded_rules,omitempty"`
	Sample        []string `json:"sample,omitempty"`
	// RefusedCode: the run would refuse the target itself (invalid, outside
	// what the caller may scan, or the run cannot be built); RefusedDetail
	// is the server's wording.
	RefusedCode   string `json:"refused_code,omitempty"`
	RefusedDetail string `json:"refused_detail,omitempty"`
	// Discovery is set when a wildcard matches no known name and a
	// subdomain discovery tool is available.
	Discovery *QuickPreviewDiscovery `json:"discovery,omitempty"`
}

// QuickScanPreview is the preview of a Quick Scan.
type QuickScanPreview struct {
	Targets []QuickPreviewTarget `json:"targets"`
	// NotPreviewed counts typed targets past the bound.
	NotPreviewed int `json:"not_previewed,omitempty"`
}

// PreviewQuickScan shows what a Quick Scan of the typed targets would do.
func (s *Service) PreviewQuickScan(ctx context.Context, in QuickScanPreviewInput) (*QuickScanPreview, error) {
	tenantID, err := shared.IDFromString(in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	scanType := scan.ScanTypeSingle
	if in.WorkflowID != "" {
		scanType = scan.ScanTypeWorkflow
		wid, err := shared.IDFromString(in.WorkflowID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid workflow_id", shared.ErrValidation)
		}
		if _, err := s.usableWorkflow(ctx, tenantID, wid); err != nil {
			return nil, err
		}
	}
	out := &QuickScanPreview{Targets: []QuickPreviewTarget{}}
	seen := map[string]bool{}
	for _, raw := range in.Targets {
		t := strings.TrimSpace(raw)
		if t == "" || seen[strings.ToLower(t)] {
			continue
		}
		seen[strings.ToLower(t)] = true
		if len(out.Targets) >= maxQuickPreviewTargets {
			out.NotPreviewed++
			continue
		}
		p, err := s.previewQuickTarget(ctx, tenantID, in, scanType, t)
		if err != nil {
			return nil, err
		}
		out.Targets = append(out.Targets, *p)
	}
	return out, nil
}

func (s *Service) previewQuickTarget(ctx context.Context, tenantID shared.ID, in QuickScanPreviewInput, scanType scan.ScanType, t string) (*QuickPreviewTarget, error) {
	p := &QuickPreviewTarget{Target: t, Kind: QuickKindHost}
	switch {
	case IsWildcardTarget(t):
		p.Kind = QuickKindWildcard
	case isCIDRTarget(t):
		p.Kind = QuickKindCIDR
	}
	if err := validateSelectorTargets([]string{t}); err != nil {
		p.RefusedCode, p.RefusedDetail = QuickRefusedInvalid, err.Error()
		return p, nil //nolint:nilerr // a refusal is the preview's answer, not a failure
	}
	// The run's own checks first: what it would refuse is reported, not
	// resolved (resolving free text would let a member probe the resolver).
	accepted, rejected, err := s.previewValidateTargets(ctx, in.TenantID, []string{t})
	if err != nil {
		return nil, err
	}
	if len(rejected) > 0 || len(accepted) == 0 {
		p.RefusedCode = QuickRefusedNotAllowed
		if len(rejected) > 0 {
			p.RefusedDetail = rejected[0].Reason
		}
		return p, nil
	}
	sc := &scan.Scan{
		TenantID:    tenantID,
		Name:        previewScanName,
		ScanType:    scanType,
		ScannerName: in.ScannerName,
		Targets:     accepted,
		CreatedBy:   userIDPtr(in.UserID),
	}
	resolved, err := s.resolveScanTargets(context.WithValue(ctx, hideOutOfDataScopeKey{}, true), sc)
	if err != nil {
		var de *shared.DomainError
		if errors.As(err, &de) {
			p.RefusedCode, p.RefusedDetail = QuickRefusedRun, de.Message
			return p, nil
		}
		return nil, err
	}
	for _, e := range resolved.Expansion {
		p.Known += e.Matched
		p.Capped = p.Capped || e.Capped
	}
	p.InScope = len(resolved.Targets)
	for _, n := range resolved.Targets {
		if len(p.Sample) == quickPreviewSampleSize {
			break
		}
		p.Sample = append(p.Sample, n)
	}
	skip := func(reason string, n int) {
		if n > 0 {
			p.Skipped = append(p.Skipped, QuickPreviewSkip{Reason: reason, Count: n})
		}
	}
	skip(SkipExcluded, resolved.Excluded)
	skip(SkipOutOfScope, resolved.OutOfScope)
	skip(SkipNotConfirmed, resolved.Unconfirmed)
	skip(SkipTierExceeded, resolved.TierExceeded)
	skip(SkipInternalNoZone, resolved.InternalOutsideZones)
	skip(SkipIncompatibleType, resolved.Incompatible)
	skip(SkipArchived, resolved.Archived)
	for _, d := range resolved.ExcludedDetail {
		for _, r := range d.Rules {
			if len(p.ExcludedRules) < maxQuickPreviewRules && !slices.Contains(p.ExcludedRules, r.Pattern) {
				p.ExcludedRules = append(p.ExcludedRules, r.Pattern)
			}
		}
	}
	if p.Kind == QuickKindWildcard && p.Known == 0 {
		p.Discovery = s.discoveryFor(ctx, tenantID, in.ScannerName, WildcardRoot(t))
	}
	return p, nil
}

// discoveryFor names an active subdomain discovery tool that can enumerate
// root, or nil: none is installed, or the run's own scanner already is one.
func (s *Service) discoveryFor(ctx context.Context, tenantID shared.ID, scanner, root string) *QuickPreviewDiscovery {
	if rootsOnlyTool(scanner) || s.toolRepo == nil {
		return nil
	}
	st, ok := stage.Lookup(stage.DiscoverSubdomains)
	if !ok {
		return nil
	}
	for _, name := range st.Tools() {
		if tl, err := s.toolRepo.GetByName(ctx, tenantID, name); err == nil && tl != nil && tl.IsActive {
			return &QuickPreviewDiscovery{Tool: name, Root: root}
		}
	}
	return nil
}
