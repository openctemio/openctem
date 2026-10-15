package finding

// Whole-tenant preview of a change of the settings that feed finding
// priority (docs/architecture/scoring-versions.md, "Preview before apply").

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// previewFindingPage is how many open findings one preview step classifies.
const previewFindingPage = 1000

// PriorityClassChange counts the open findings that move between classes.
type PriorityClassChange struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Count int    `json:"count"`
}

// PriorityImpact is what a settings change would do to the tenant's open
// findings.
type PriorityImpact struct {
	OpenFindings        int                   `json:"open_findings"`
	Changed             int                   `json:"changed"`
	Raised              int                   `json:"raised"`
	Lowered             int                   `json:"lowered"`
	ClassChanges        []PriorityClassChange `json:"class_changes"`
	DeadlinesTightened  int                   `json:"deadlines_tightened"`
	TicketsAffected     int                   `json:"tickets_affected"`
	ManualOverridesKept int                   `json:"manual_overrides_kept"`
}

// DeadlineFor returns the deadline an open finding would get with the given
// class if its SLA were counted from now (zero = no SLA). The preview uses it
// to count the deadlines that would tighten (min(old, now + SLA)).
type DeadlineFor func(f *vulnerability.Finding, class vulnerability.PriorityClass, now time.Time) time.Time

// PreviewOwnershipFloor classifies every open finding of the tenant as the
// finding-priority worker would with the ownership floor set to enabled, and
// compares the result with the stored class. Read-only: nothing is persisted
// and no event is emitted.
func (s *PriorityClassificationService) PreviewOwnershipFloor(ctx context.Context, tenantID shared.ID, enabled bool, deadline DeadlineFor) (*PriorityImpact, error) {
	ctx = context.WithValue(ctx, floorOverrideKey{}, enabled)
	rules, err := s.ruleRepo.ListActiveByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load priority rules: %w", err)
	}
	filter := vulnerability.NewFindingFilter().WithTenantID(tenantID)
	filter.Statuses = vulnerability.OpenStatuses()
	opts := vulnerability.NewFindingListOptions().WithSort(
		pagination.NewSortOption(vulnerability.FindingAllowedSortFields()).Parse("created_at"))

	out := &PriorityImpact{ClassChanges: []PriorityClassChange{}}
	moves := map[[2]string]int{}
	now := time.Now().UTC()
	assets := map[shared.ID]*asset.Asset{}
	for pageNum := 1; ; pageNum++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		res, err := s.findingRepo.List(ctx, filter, opts, pagination.Pagination{Page: pageNum, PerPage: previewFindingPage})
		if err != nil {
			return nil, fmt.Errorf("list open findings: %w", err)
		}
		pageAssets, err := s.previewPageAssets(ctx, tenantID, res.Data, assets, out)
		if err != nil {
			return nil, err
		}
		for _, fc := range s.enrichAndContextualize(ctx, tenantID, res.Data, pageAssets) {
			tallyPreview(out, moves, fc.finding, classifyContext(rules, fc.pctx).Class, deadline, now)
		}
		if len(res.Data) < previewFindingPage {
			break
		}
	}
	for k, n := range moves {
		out.ClassChanges = append(out.ClassChanges, PriorityClassChange{From: k[0], To: k[1], Count: n})
	}
	sort.Slice(out.ClassChanges, func(i, j int) bool {
		a, b := out.ClassChanges[i], out.ClassChanges[j]
		if a.From != b.From {
			return a.From < b.From
		}
		return a.To < b.To
	})
	return out, nil
}

// previewPageAssets counts the page's findings and loads their assets once
// per preview (cache shared across pages).
func (s *PriorityClassificationService) previewPageAssets(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding, cache map[shared.ID]*asset.Asset, out *PriorityImpact) (map[shared.ID]*asset.Asset, error) {
	page := map[shared.ID]*asset.Asset{}
	for _, f := range findings {
		out.OpenFindings++
		if f.PriorityClassOverride() {
			out.ManualOverridesKept++
		}
		aid := f.AssetID()
		if aid.IsZero() {
			continue
		}
		a, seen := cache[aid]
		if !seen {
			var err error
			a, err = s.assetRepo.GetByID(ctx, tenantID, aid)
			if err != nil && !errors.Is(err, shared.ErrNotFound) {
				return nil, fmt.Errorf("load asset: %w", err)
			}
			cache[aid] = a
		}
		if a != nil {
			page[aid] = a
		}
	}
	return page, nil
}

// tallyPreview records one finding's would-be class against its stored one.
func tallyPreview(out *PriorityImpact, moves map[[2]string]int, f *vulnerability.Finding, class vulnerability.PriorityClass, deadline DeadlineFor, now time.Time) {
	old := ""
	if pc := f.PriorityClass(); pc != nil {
		old = string(*pc)
	}
	if string(class) == old {
		return
	}
	out.Changed++
	moves[[2]string{old, string(class)}]++
	if old == "" || string(class) < old {
		out.Raised++
		if d := f.SLADeadline(); d != nil && deadline != nil {
			if nd := deadline(f, class, now); !nd.IsZero() && nd.Before(*d) {
				out.DeadlinesTightened++
			}
		}
	} else {
		out.Lowered++
	}
	if len(f.WorkItemURIs()) > 0 {
		out.TicketsAffected++
	}
}
