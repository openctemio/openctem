package threatmodel

import (
	"sort"

	tmdom "github.com/openctemio/api/pkg/domain/threatmodel"
)

// TechniqueMeta is the catalog enrichment for one ATT&CK technique: its display
// name and the full set of mitigations the catalog maps to it. It is looked up
// by technique id when building the coverage matrix. Both fields are optional —
// when the catalog is unavailable buildCoverage degrades to the facts carried on
// the threats themselves (empty name, mitigation ids taken from the threats).
type TechniqueMeta struct {
	Name          string
	MitigationIDs []string
}

// StatusCounts is the per-status breakdown of the threats behind one technique
// cell. The sum equals TechniqueCoverage.ThreatCount.
type StatusCounts struct {
	Open        int
	Mitigated   int
	Covered     int
	Accepted    int
	Theoretical int
}

// TechniqueCoverage is one technique cell in the tactic × technique matrix. It
// carries the worst-case status rollup plus the per-status detail so a heatmap
// can color by Status and a tooltip can show the breakdown, and so an ATT&CK
// Navigator layer can be produced client-side from TechniqueID + Status/MaxScore.
type TechniqueCoverage struct {
	TechniqueID   string
	TechniqueName string
	Status        string
	Counts        StatusCounts
	MaxScore      float64
	MitigationIDs []string
	ThreatCount   int
}

// TacticCoverage groups the technique cells that share a tactic (by tactic name
// as stored on the threats).
type TacticCoverage struct {
	Tactic     string
	Techniques []TechniqueCoverage
}

// CoverageTotals is the model-wide rollup over the technique cells (not the raw
// threats): how many distinct technique cells exist and how they distribute over
// the worst-case statuses, plus a coverage percentage.
type CoverageTotals struct {
	Techniques  int
	Open        int
	Mitigated   int
	Covered     int
	Accepted    int
	Theoretical int
	CoveragePct float64
}

// Coverage is the aggregated tactic × technique coverage matrix for a model. The
// envelope facts (model id, dataset version, generated_at) are added by the
// handler from the model; buildCoverage returns only the matrix + totals.
type Coverage struct {
	Tactics []TacticCoverage
	Totals  CoverageTotals
}

// killChainOrder is the canonical MITRE ATT&CK Enterprise tactic order
// (Reconnaissance → … → Impact). Tactics are emitted in this order; any tactic
// not in this list (e.g. a future/custom tactic) sorts after all known ones,
// alphabetically, so ordering is always stable and deterministic.
var killChainOrder = []string{
	"Reconnaissance",
	"Resource Development",
	"Initial Access",
	"Execution",
	"Persistence",
	"Privilege Escalation",
	"Defense Evasion",
	"Credential Access",
	"Discovery",
	"Lateral Movement",
	"Collection",
	"Command and Control",
	"Exfiltration",
	"Impact",
}

var tacticRank = func() map[string]int {
	m := make(map[string]int, len(killChainOrder))
	for i, t := range killChainOrder {
		m[t] = i
	}
	return m
}()

// techAgg is the mutable accumulator for one (tactic, technique) cell.
type techAgg struct {
	techniqueID string
	tactic      string
	counts      StatusCounts
	worstRank   int
	worstStatus tmdom.ThreatStatus
	maxScore    float64
	threatCount int
	mitigations map[string]bool
}

// buildCoverage aggregates a model's enumerated threats into a tactic × technique
// coverage matrix. It is pure and deterministic (no I/O, output ordered).
//
// Per technique cell it computes:
//   - Status: the WORST-case rollup across the cell's threats, using the
//     precedence open > accepted > mitigated > covered > theoretical (the same
//     precedence as statusRank). A technique is "open" if ANY of its threats is
//     open.
//   - Counts: the per-status threat breakdown (sums to ThreatCount).
//   - MaxScore: the highest threat score in the cell.
//   - MitigationIDs: the catalog mitigations for the technique (meta), falling
//     back to the distinct mitigation ids carried on the threats.
//
// meta may be nil/empty; the aggregation still works (empty technique names,
// mitigation ids sourced from the threats). Threats with an empty TechniqueID are
// skipped (they cannot be placed in the matrix).
func buildCoverage(threats []*tmdom.ThreatModelThreat, meta map[string]TechniqueMeta) Coverage {
	// key: tactic + "\x00" + techniqueID → one cell.
	cells := make(map[string]*techAgg)
	for _, t := range threats {
		if t == nil || t.TechniqueID == "" {
			continue
		}
		key := t.Tactic + "\x00" + t.TechniqueID
		c := cells[key]
		if c == nil {
			c = &techAgg{
				techniqueID: t.TechniqueID,
				tactic:      t.Tactic,
				mitigations: make(map[string]bool),
			}
			cells[key] = c
		}
		c.threatCount++
		switch t.Status {
		case tmdom.StatusOpen:
			c.counts.Open++
		case tmdom.StatusMitigated:
			c.counts.Mitigated++
		case tmdom.StatusCovered:
			c.counts.Covered++
		case tmdom.StatusAccepted:
			c.counts.Accepted++
		case tmdom.StatusTheoretical:
			c.counts.Theoretical++
		}
		if r := statusRank(t.Status); r > c.worstRank || c.worstStatus == "" {
			c.worstRank = r
			c.worstStatus = t.Status
		}
		if t.Score > c.maxScore {
			c.maxScore = t.Score
		}
		if t.MitigationID != "" {
			c.mitigations[t.MitigationID] = true
		}
	}

	byTactic := groupByTactic(cells, meta)
	return Coverage{Tactics: byTactic, Totals: totalsFor(byTactic)}
}

// groupByTactic turns the flat cell map into tactic-ordered groups with
// technique cells ordered by technique id, applying catalog enrichment.
func groupByTactic(cells map[string]*techAgg, meta map[string]TechniqueMeta) []TacticCoverage {
	groups := make(map[string][]TechniqueCoverage)
	for _, c := range cells {
		tc := TechniqueCoverage{
			TechniqueID:   c.techniqueID,
			Status:        c.worstStatus.String(),
			Counts:        c.counts,
			MaxScore:      c.maxScore,
			ThreatCount:   c.threatCount,
			MitigationIDs: mitigationsFor(c, meta),
		}
		if m, ok := meta[c.techniqueID]; ok {
			tc.TechniqueName = m.Name
		}
		groups[c.tactic] = append(groups[c.tactic], tc)
	}

	tactics := make([]string, 0, len(groups))
	for tac := range groups {
		tactics = append(tactics, tac)
	}
	sort.Slice(tactics, func(i, j int) bool { return tacticLess(tactics[i], tactics[j]) })

	out := make([]TacticCoverage, 0, len(tactics))
	for _, tac := range tactics {
		techs := groups[tac]
		sort.Slice(techs, func(i, j int) bool { return techs[i].TechniqueID < techs[j].TechniqueID })
		out = append(out, TacticCoverage{Tactic: tac, Techniques: techs})
	}
	return out
}

// mitigationsFor returns the catalog mitigations for the cell's technique, or the
// distinct mitigation ids carried on its threats when the catalog has none.
func mitigationsFor(c *techAgg, meta map[string]TechniqueMeta) []string {
	if m, ok := meta[c.techniqueID]; ok && len(m.MitigationIDs) > 0 {
		ids := append([]string(nil), m.MitigationIDs...)
		sort.Strings(ids)
		return ids
	}
	if len(c.mitigations) == 0 {
		return nil
	}
	ids := make([]string, 0, len(c.mitigations))
	for id := range c.mitigations {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// tacticLess orders tactics by the canonical kill-chain order, with unknown
// tactics after all known ones (alphabetically among themselves).
func tacticLess(a, b string) bool {
	ra, aok := tacticRank[a]
	rb, bok := tacticRank[b]
	switch {
	case aok && bok:
		return ra < rb
	case aok:
		return true
	case bok:
		return false
	default:
		return a < b
	}
}

// totalsFor rolls the technique cells up to model-wide totals. Each cell counts
// once, by its worst-case status. coverage_pct mirrors the model rollup formula:
// (mitigated+covered+accepted) / (open+mitigated+covered+accepted) — theoretical
// cells count toward the technique total but are neither open nor addressed.
func totalsFor(tactics []TacticCoverage) CoverageTotals {
	var tot CoverageTotals
	for _, tac := range tactics {
		for _, tc := range tac.Techniques {
			tot.Techniques++
			switch tmdom.ThreatStatus(tc.Status) {
			case tmdom.StatusOpen:
				tot.Open++
			case tmdom.StatusMitigated:
				tot.Mitigated++
			case tmdom.StatusCovered:
				tot.Covered++
			case tmdom.StatusAccepted:
				tot.Accepted++
			case tmdom.StatusTheoretical:
				tot.Theoretical++
			}
		}
	}
	addressed := tot.Mitigated + tot.Covered + tot.Accepted
	denom := tot.Open + addressed
	if denom > 0 {
		tot.CoveragePct = float64(addressed) / float64(denom) * 100
	}
	return tot
}
