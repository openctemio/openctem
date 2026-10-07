// Package easm serves the External Attack Surface Management overview
// (RFC-036 §6.10, GET /api/v1/easm/summary): the surface, how much of it is
// attributed, what is new, the open external exposures and how fresh the
// passive monitoring is.
package easm

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SummaryReader is the aggregate query the overview needs.
type SummaryReader interface {
	Summary(ctx context.Context, tenantID shared.ID, scopeUserID *shared.ID, now time.Time, topN int) (*SummaryData, error)
}

// SummaryData is the raw summary the repository returns.
type SummaryData struct {
	AssetsByType       map[string]int
	ExposedServices    int
	AttributionByState map[string]int // "" = legacy (no record)
	OldestReviewSince  *time.Time
	ReviewByReason     map[string]int // review queue (needs_review, candidate) by rule
	NewSince7d         int
	NewSince30d        int
	CycleStart         *time.Time
	NewSinceCycle      int
	OpenBySeverity     map[string]int
	OpenByType         map[string]int
	TopRisks           []RiskRow
	CTWatched          int
	CTFailing          int
	CTOldestSuccess    *time.Time
	CTNeverSucceeded   int
}

// RiskRow is one open exposure on the external surface.
type RiskRow struct {
	ID        string
	Type      string
	Severity  string
	Title     string
	AssetID   *string
	AssetName *string
	LastSeen  time.Time
}

// Service builds the overview.
type Service struct {
	repo      SummaryReader
	dataScope *datascope.Enforcer
	now       func() time.Time
}

// NewService creates the service. A nil enforcer means unrestricted reads.
func NewService(repo SummaryReader, scope *datascope.Enforcer) *Service {
	return &Service{repo: repo, dataScope: scope, now: func() time.Time { return time.Now().UTC() }}
}

// topRisks is how many open exposures the overview lists.
const topRisks = 10

// Summary is the overview response.
type Summary struct {
	Surface     SurfaceBlock     `json:"surface"`
	Attribution AttributionBlock `json:"attribution"`
	New         NewBlock         `json:"new"`
	Exposures   ExposureBlock    `json:"exposures"`
	TopRisks    []Risk           `json:"top_risks"`
	Monitoring  MonitoringBlock  `json:"monitoring"`
	GeneratedAt time.Time        `json:"generated_at"`
}

// SurfaceBlock counts the external surface.
type SurfaceBlock struct {
	Total           int            `json:"total"`
	ByType          map[string]int `json:"by_type"`
	ExposedServices int            `json:"exposed_services"`
}

// AttributionBlock counts assets by attribution state. Legacy counts assets
// with no attribution record (in the inventory before EASM; confirmed).
type AttributionBlock struct {
	Confirmed   int        `json:"confirmed"`
	Legacy      int        `json:"legacy"`
	NeedsReview int        `json:"needs_review"`
	Candidate   int        `json:"candidate"`
	Dependency  int        `json:"dependency"`
	MonitorOnly int        `json:"monitor_only"`
	Rejected    int        `json:"rejected"`
	ReviewSince *time.Time `json:"review_oldest_since,omitempty"`
	// ReviewByReason counts the review queue (needs_review and candidate)
	// by the rule that put each asset there (RFC-054 §6.6).
	ReviewByReason map[string]int `json:"review_by_reason"`
}

// NewBlock counts surface assets first seen recently. CycleStart is the
// activation of the latest CTEM cycle; SinceCycle is null without one.
type NewBlock struct {
	Last7Days  int        `json:"last_7_days"`
	Last30Days int        `json:"last_30_days"`
	CycleStart *time.Time `json:"cycle_start,omitempty"`
	SinceCycle *int       `json:"since_cycle,omitempty"`
}

// ExposureBlock counts open external exposures.
type ExposureBlock struct {
	Open       int            `json:"open"`
	BySeverity map[string]int `json:"by_severity"`
	ByType     []TypeCount    `json:"by_type"`
}

// TypeCount is one exposure type's open count.
type TypeCount struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

// Risk is one open exposure in the top list.
type Risk struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
	Title     string    `json:"title"`
	AssetID   *string   `json:"asset_id,omitempty"`
	AssetName *string   `json:"asset_name,omitempty"`
	LastSeen  time.Time `json:"last_seen"`
}

// MonitoringBlock is the freshness of the passive CT monitoring.
type MonitoringBlock struct {
	CTDomainsWatched int        `json:"ct_domains_watched"`
	CTFailing        int        `json:"ct_failing"`
	CTNeverQueried   int        `json:"ct_never_succeeded"`
	CTOldestSuccess  *time.Time `json:"ct_oldest_success,omitempty"`
}

// Summary returns the overview for the caller, narrowed to its data scope.
func (s *Service) Summary(ctx context.Context, tenantID shared.ID) (*Summary, error) {
	var scopeUser *shared.ID
	if s.dataScope != nil {
		scope, err := s.dataScope.Resolve(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("resolve data scope: %w", err)
		}
		if scope != nil {
			id := scope.UserID
			scopeUser = &id
		}
	}
	now := s.now()
	d, err := s.repo.Summary(ctx, tenantID, scopeUser, now, topRisks)
	if err != nil {
		return nil, err
	}
	return build(d, now), nil
}

func build(d *SummaryData, now time.Time) *Summary {
	out := &Summary{GeneratedAt: now, TopRisks: []Risk{}}
	out.Surface.ByType = map[string]int{}
	for t, n := range d.AssetsByType {
		out.Surface.ByType[t] = n
		out.Surface.Total += n
	}
	out.Surface.ExposedServices = d.ExposedServices

	a := &out.Attribution
	a.Legacy = d.AttributionByState[""]
	a.Confirmed = d.AttributionByState["confirmed"] + a.Legacy
	a.NeedsReview = d.AttributionByState["needs_review"]
	a.Candidate = d.AttributionByState["candidate"]
	a.Dependency = d.AttributionByState["dependency"]
	a.MonitorOnly = d.AttributionByState["monitor_only"]
	a.Rejected = d.AttributionByState["rejected"]
	a.ReviewSince = d.OldestReviewSince
	a.ReviewByReason = map[string]int{}
	for k, v := range d.ReviewByReason {
		a.ReviewByReason[k] = v
	}

	out.New = NewBlock{Last7Days: d.NewSince7d, Last30Days: d.NewSince30d, CycleStart: d.CycleStart}
	if d.CycleStart != nil {
		n := d.NewSinceCycle
		out.New.SinceCycle = &n
	}

	out.Exposures.BySeverity = map[string]int{}
	for sev, n := range d.OpenBySeverity {
		out.Exposures.BySeverity[sev] = n
		out.Exposures.Open += n
	}
	out.Exposures.ByType = make([]TypeCount, 0, len(d.OpenByType))
	for t, n := range d.OpenByType {
		out.Exposures.ByType = append(out.Exposures.ByType, TypeCount{Type: t, Count: n})
	}
	sort.Slice(out.Exposures.ByType, func(i, j int) bool {
		if out.Exposures.ByType[i].Count != out.Exposures.ByType[j].Count {
			return out.Exposures.ByType[i].Count > out.Exposures.ByType[j].Count
		}
		return out.Exposures.ByType[i].Type < out.Exposures.ByType[j].Type
	})
	for _, r := range d.TopRisks {
		out.TopRisks = append(out.TopRisks, Risk(r))
	}
	out.Monitoring = MonitoringBlock{CTDomainsWatched: d.CTWatched, CTFailing: d.CTFailing,
		CTNeverQueried: d.CTNeverSucceeded, CTOldestSuccess: d.CTOldestSuccess}
	return out
}
