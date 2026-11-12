package exploration

// Scoring and selection of the frontier (docs/architecture/exploration.md,
// "Scoring and dispatch"). Code decides; an opener only gives a likelihood
// band. The score is the expected value of a step:
//
//	score = P(useful) x value(subject) / expected cost
//
// P is the band's prior updated by the tenant's own outcomes of the same
// (lead type, capability) cell; value comes from the subject's criticality,
// exposure, open KEV or critical findings and crown jewel mark; cost is the
// tool's learned mean duration for the tenant.

import (
	"math"
	"sort"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
)

// Scoring constants.
const (
	// PriorStrength is how many outcomes the prior band weighs.
	PriorStrength = 4.0
	// ReserveShare of each pass's dispatch slots goes to untried cells.
	ReserveShare = 0.2
	// DemoteAfter outcomes of a cell with none useful demote it.
	DemoteAfter = 10
	// DemoteFactor multiplies a demoted cell's score.
	DemoteFactor = 0.2
	// DefaultCostSeconds is the cost of a tool with no learned duration.
	DefaultCostSeconds = 60.0
	// MinCostSeconds floors the learned cost.
	MinCostSeconds = 1.0
)

// CellStats are a tenant's outcomes of one (lead type, capability) cell:
// all settled steps, the useful ones (proven), and the same over the last
// DemoteAfter settled steps.
type CellStats struct {
	Tried        int
	Useful       int
	RecentTried  int
	RecentUseful int
}

// CellKey identifies a cell.
func CellKey(leadType, capability string) string { return leadType + "|" + capability }

// SubjectValue are the facts of a subject the value reads.
type SubjectValue struct {
	Criticality   string
	Public        bool
	KEVOrCritical bool
	CrownJewel    bool
}

// ScoreInput is everything one lead's score reads.
type ScoreInput struct {
	Likelihood  Likelihood
	Cell        CellStats
	ValueWeight float64
	Subject     SubjectValue
	// MeanMs is the tool's learned mean duration (0: unknown).
	MeanMs float64
}

func criticalityWeight(c string) float64 {
	switch asset.Criticality(c) {
	case asset.CriticalityCritical:
		return 4
	case asset.CriticalityHigh:
		return 3
	case asset.CriticalityMedium:
		return 2
	}
	return 1
}

func round3(f float64) float64 { return math.Round(f*1000) / 1000 }

// Score returns the lead's score and the inputs it was computed from (kept
// with the lead, so a person can see why it ranks where it does).
func Score(in ScoreInput) (float64, map[string]any) {
	p := (in.Likelihood.Prior()*PriorStrength + float64(in.Cell.Useful)) / (PriorStrength + float64(in.Cell.Tried))
	value := criticalityWeight(in.Subject.Criticality)
	if in.Subject.Public {
		value *= 2
	}
	if in.Subject.KEVOrCritical {
		value *= 3
	}
	if in.Subject.CrownJewel {
		value *= 2
	}
	if in.ValueWeight > 0 {
		value *= in.ValueWeight
	}
	cost := DefaultCostSeconds
	if in.MeanMs > 0 {
		cost = math.Max(in.MeanMs/1000, MinCostSeconds)
	}
	demoted := in.Cell.RecentTried >= DemoteAfter && in.Cell.RecentUseful == 0
	score := p * value / cost * 100
	if demoted {
		score *= DemoteFactor
	}
	return round3(score), map[string]any{
		"p_useful": round3(p), "value": round3(value), "cost_seconds": round3(cost),
		"tried": in.Cell.Tried, "useful": in.Cell.Useful, "demoted": demoted,
	}
}

// Select picks up to slots leads to dispatch from open leads (already
// scored). A share of the slots (ReserveShare, at least one when there is
// an untried cell) goes first to leads of cells the tenant never settled, so
// new kinds of step get tried; the rest goes by score. At most one lead per
// subject and capability is picked, and none whose (subject, capability)
// already runs (busy).
func Select(open []*Lead, cells map[string]CellStats, busy map[string]bool, slots int) []*Lead {
	if slots <= 0 || len(open) == 0 {
		return nil
	}
	sorted := append([]*Lead(nil), open...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Score != sorted[j].Score {
			return sorted[i].Score > sorted[j].Score
		}
		return sorted[i].CreatedAt.Before(sorted[j].CreatedAt)
	})
	taken := map[string]bool{}
	for k := range busy {
		taken[k] = true
	}
	var out []*Lead
	pick := func(l *Lead) bool {
		if l.SubjectAssetID == nil {
			return false
		}
		k := l.SubjectAssetID.String() + "|" + l.Action.Capability
		if taken[k] {
			return false
		}
		taken[k] = true
		out = append(out, l)
		return true
	}
	reserve := int(math.Ceil(float64(slots) * ReserveShare))
	picked := map[*Lead]bool{}
	for _, l := range sorted {
		if len(out) >= reserve {
			break
		}
		if cells[CellKey(l.Type, l.Action.Capability)].Tried == 0 && pick(l) {
			picked[l] = true
		}
	}
	for _, l := range sorted {
		if len(out) >= slots {
			break
		}
		if !picked[l] {
			pick(l)
		}
	}
	return out
}

// BusyKey is the key Select uses for a running (subject, capability).
func BusyKey(subject, capability string) string { return subject + "|" + capability }
