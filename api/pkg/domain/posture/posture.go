// Package posture is the external attack surface posture score: one grade
// from A to F for an organization and for each of its root domains, with
// the contribution of each category of issue and what to fix to reach the
// next grade. Design and formula: docs/architecture/easm-posture.md.
//
// The score is pure arithmetic over per-asset points that the platform
// precomputes into easm_posture_assets on a schedule; a read sums the
// points of the assets the reader may see and calls Compute. Every constant
// of the formula is in this file.
package posture

import (
	"math"
	"sort"
)

// Category is a kind of issue the score counts.
type Category string

// The categories, in display order.
const (
	// CatVulnerabilities: open findings on the surface (published, not
	// pentest), per finding.
	CatVulnerabilities Category = "vulnerabilities"
	// CatHijackable: dangling CNAME / NS records and confirmed subdomain
	// takeovers, at most one issue per asset (its worst).
	CatHijackable Category = "hijackable_subdomains"
	// CatExposedServices: open ports, detected services and exposed APIs
	// or interfaces, per exposure.
	CatExposedServices Category = "exposed_services"
	// CatCloudStorage: publicly readable storage buckets, per exposure.
	CatCloudStorage Category = "cloud_storage"
	// CatMisconfiguration: TLS issues, expiring or expired certificates,
	// weak email security, missing headers, public repositories and other
	// misconfigurations, per exposure.
	CatMisconfiguration Category = "misconfiguration"
	// CatSuspicious: leaked credentials, lookalike domains and sensitive
	// data exposed, per exposure.
	CatSuspicious Category = "suspicious_activity"
)

// NumCategories is the number of categories.
const NumCategories = 6

// Categories returns the categories in display order. Their index is the
// index of Sums.Points and Sums.Issues.
func Categories() []Category {
	return []Category{CatVulnerabilities, CatHijackable, CatExposedServices, CatCloudStorage, CatMisconfiguration, CatSuspicious}
}

// Weight is how much of the 100 points a category can take away (Max), and
// how many points per surface asset make it take half of that (HalfPerAsset).
type Weight struct {
	Max          float64
	HalfPerAsset float64
}

// weights: the Max values add up to 100. A small HalfPerAsset means a few
// issues already weigh a lot (one hijackable name on a hundred assets takes
// a third of its category).
var weights = [NumCategories]Weight{
	{Max: 35, HalfPerAsset: 2.0}, // vulnerabilities
	{Max: 15, HalfPerAsset: 0.2}, // hijackable subdomains
	{Max: 15, HalfPerAsset: 1.0}, // exposed services
	{Max: 10, HalfPerAsset: 0.2}, // cloud storage
	{Max: 15, HalfPerAsset: 1.0}, // misconfiguration
	{Max: 10, HalfPerAsset: 0.5}, // suspicious activity
}

// WeightOf returns a category's weight (zero for an unknown category).
func WeightOf(c Category) Weight {
	if i := IndexOf(c); i >= 0 {
		return weights[i]
	}
	return Weight{}
}

// IndexOf returns the index of a category, -1 when unknown.
func IndexOf(c Category) int {
	for i, x := range Categories() {
		if x == c {
			return i
		}
	}
	return -1
}

// MinSurface is the smallest surface the half-points are scaled to, so a
// handful of assets is not graded on one issue alone.
const MinSurface = 10

// KEVMultiplier multiplies the points of a finding whose CVE is known
// exploited.
const KEVMultiplier = 2.0

// SeverityPoints are the points of one issue by severity. Informational
// issues carry none.
var SeverityPoints = map[string]float64{"critical": 10, "high": 5, "medium": 2, "low": 0.5}

// CriticalityMultipliers scale every point of an asset by how much the
// asset matters. A crown jewel counts as critical.
var CriticalityMultipliers = map[string]float64{"critical": 2, "high": 1.5, "medium": 1, "low": 0.5}

// Criticalities are the asset criticality levels, most critical first.
func Criticalities() []string { return []string{"critical", "high", "medium", "low"} }

// Multiplier is the point multiplier of an asset. An unknown level counts
// as medium.
func Multiplier(criticality string, crownJewel bool) float64 {
	if crownJewel {
		return CriticalityMultipliers["critical"]
	}
	if m, ok := CriticalityMultipliers[criticality]; ok {
		return m
	}
	return 1
}

// EffectiveCriticality is the level an asset's points are grouped under:
// critical for a crown jewel, medium for an unknown level.
func EffectiveCriticality(criticality string, crownJewel bool) string {
	if crownJewel {
		return "critical"
	}
	if _, ok := CriticalityMultipliers[criticality]; ok {
		return criticality
	}
	return "medium"
}

// ExposureCategory maps an exposure event type to its category; ok is
// false for types the score does not count (changes and removals such as
// port_closed or subdomain_discovered, and identity exposures, which are
// not part of the external surface).
func ExposureCategory(eventType string) (Category, bool) {
	switch eventType {
	case "dangling_cname", "dangling_ns", "subdomain_takeover":
		return CatHijackable, true
	case "port_open", "service_detected", "api_exposed", "web_interface_exposed", "mcp_server_exposed":
		return CatExposedServices, true
	case "bucket_public":
		return CatCloudStorage, true
	case "ssl_issue", "certificate_expiring", "certificate_expired", "email_security_weak",
		"header_missing", "misconfiguration", "repo_public":
		return CatMisconfiguration, true
	case "credential_leaked", "lookalike_domain", "sensitive_data_exposed", "mail_server_blocklisted":
		return CatSuspicious, true
	}
	return "", false
}

// ExposureTypes returns every exposure type the score counts, grouped by
// category in display order (stable: used to build SQL).
func ExposureTypes() map[Category][]string {
	out := map[Category][]string{}
	for _, t := range []string{
		"dangling_cname", "dangling_ns", "subdomain_takeover",
		"port_open", "service_detected", "api_exposed", "web_interface_exposed", "mcp_server_exposed",
		"bucket_public",
		"ssl_issue", "certificate_expiring", "certificate_expired", "email_security_weak", "header_missing", "misconfiguration", "repo_public",
		"credential_leaked", "lookalike_domain", "sensitive_data_exposed", "mail_server_blocklisted",
	} {
		c, _ := ExposureCategory(t)
		out[c] = append(out[c], t)
	}
	return out
}

// Sums are the summed points and issue counts of a set of surface assets.
type Sums struct {
	// Assets is the number of surface assets (issues without an asset add
	// points but no asset).
	Assets int64
	Points [NumCategories]float64
	Issues [NumCategories]int64
}

// Add adds o to s.
func (s *Sums) Add(o Sums) {
	s.Assets += o.Assets
	for i := range s.Points {
		s.Points[i] += o.Points[i]
		s.Issues[i] += o.Issues[i]
	}
}

// Minus returns s without o (points never below zero).
func (s Sums) Minus(o Sums) Sums {
	out := s
	for i := range out.Points {
		out.Points[i] = math.Max(0, out.Points[i]-o.Points[i])
		out.Issues[i] = max(0, out.Issues[i]-o.Issues[i])
	}
	return out
}

// Grades, best first, with the lowest score of each.
var gradeFloors = []struct {
	Grade string
	Floor int
}{{"A", 90}, {"B", 80}, {"C", 70}, {"D", 60}, {"F", 0}}

// GradeOf returns the grade of a score (0..100).
func GradeOf(score int) string {
	for _, g := range gradeFloors {
		if score >= g.Floor {
			return g.Grade
		}
	}
	return "F"
}

// NextGrade returns the grade above g and its lowest score; ok is false for A.
func NextGrade(g string) (grade string, floor int, ok bool) {
	for i, x := range gradeFloors {
		if x.Grade == g && i > 0 {
			return gradeFloors[i-1].Grade, gradeFloors[i-1].Floor, true
		}
	}
	return "", 0, false
}

// CategoryScore is one category's part of a score.
type CategoryScore struct {
	Category Category
	// Max is the most the category can take away.
	Max    float64
	Points float64
	Issues int64
	// Deduction is what it takes away now.
	Deduction float64
}

// Score is a computed score.
type Score struct {
	// Measured is false when there is no surface asset (no score, never
	// an A by default).
	Measured bool
	Assets   int64
	// Raw is 100 minus the deductions; Value is Raw rounded down, and the
	// grade follows Value.
	Raw        float64
	Value      int
	Grade      string
	Categories []CategoryScore
}

// half is the points at which category i takes half its weight.
func half(i int, assets int64) float64 {
	return weights[i].HalfPerAsset * float64(max(assets, MinSurface))
}

// deduction is what category i takes away for p points.
func deduction(i int, p float64, assets int64) float64 {
	if p <= 0 {
		return 0
	}
	return weights[i].Max * p / (p + half(i, assets))
}

// Compute scores a set of sums:
//
//	deduction(c) = Max(c) * P(c) / (P(c) + HalfPerAsset(c) * max(assets, 10))
//	score        = floor(100 - sum of deductions), grade by score
//
// Each deduction grows with the points and never reaches its Max, so fixing
// any issue raises the score and no category can hide another.
func Compute(s Sums) Score {
	out := Score{Assets: s.Assets, Measured: s.Assets > 0, Raw: 100}
	for i, c := range Categories() {
		d := deduction(i, s.Points[i], s.Assets)
		out.Raw -= d
		out.Categories = append(out.Categories, CategoryScore{
			Category: c, Max: weights[i].Max, Points: round2(s.Points[i]), Issues: s.Issues[i], Deduction: round2(d),
		})
	}
	out.Raw = math.Max(0, math.Min(100, out.Raw))
	out.Value = int(math.Floor(out.Raw + 1e-9))
	out.Grade = GradeOf(out.Value)
	if !out.Measured {
		out.Grade, out.Value = "", 0
	}
	return out
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

// Item is one asset's points in one category: the unit of a fix plan.
type Item struct {
	AssetID  string
	Name     string
	Category Category
	Points   float64
	Issues   int64
}

// Urgency orders items for a fix plan: the score points an item is worth
// per point of effort do not depend on the surface size, so the order is
// fixed and can be computed in SQL (Points * Max / HalfPerAsset).
func Urgency(c Category, points float64) float64 {
	w := WeightOf(c)
	if w.HalfPerAsset <= 0 {
		return 0
	}
	return points * w.Max / w.HalfPerAsset
}

// PlanStep is one item of a fix plan with the score once it and every step
// before it are fixed.
type PlanStep struct {
	Item       Item
	ScoreAfter int
	GradeAfter string
}

// Plan is what to fix to reach the next grade.
type Plan struct {
	// Target is the next grade and Floor its lowest score; empty at A.
	Target string
	Floor  int
	// Reached is true when the steps reach Target.
	Reached bool
	Steps   []PlanStep
}

// MaxPlanSteps caps a plan.
const MaxPlanSteps = 25

// FixPlan walks items from the most urgent and returns the shortest prefix
// that lifts the score to the next grade (or every step it tried when the
// items do not reach it). items need not be sorted.
func FixPlan(s Sums, items []Item) Plan {
	cur := Compute(s)
	target, floor, ok := NextGrade(cur.Grade)
	if !cur.Measured || !ok {
		return Plan{}
	}
	sorted := append([]Item(nil), items...)
	sort.SliceStable(sorted, func(i, j int) bool {
		ui, uj := Urgency(sorted[i].Category, sorted[i].Points), Urgency(sorted[j].Category, sorted[j].Points)
		if ui != uj {
			return ui > uj
		}
		return sorted[i].AssetID < sorted[j].AssetID
	})
	p := Plan{Target: target, Floor: floor}
	work := s
	for _, it := range sorted {
		if len(p.Steps) >= MaxPlanSteps {
			break
		}
		i := IndexOf(it.Category)
		if i < 0 || it.Points <= 0 {
			continue
		}
		work.Points[i] = math.Max(0, work.Points[i]-it.Points)
		work.Issues[i] = max(0, work.Issues[i]-it.Issues)
		after := Compute(work)
		p.Steps = append(p.Steps, PlanStep{Item: it, ScoreAfter: after.Value, GradeAfter: after.Grade})
		if after.Value >= floor {
			p.Reached = true
			break
		}
	}
	return p
}

// CategoryGain is what fixing every issue of one category would give.
type CategoryGain struct {
	Category   Category
	ScoreAfter int
	GradeAfter string
}

// CategoryGains returns, per category with points, the score once all its
// issues are fixed.
func CategoryGains(s Sums) []CategoryGain {
	out := make([]CategoryGain, 0, NumCategories)
	for i, c := range Categories() {
		if s.Points[i] <= 0 {
			continue
		}
		w := s
		w.Points[i], w.Issues[i] = 0, 0
		after := Compute(w)
		out = append(out, CategoryGain{Category: c, ScoreAfter: after.Value, GradeAfter: after.Grade})
	}
	return out
}

// LevelSums are the sums of the assets of one criticality level.
type LevelSums struct {
	Criticality string
	Sums        Sums
}

// Reduction is the risk reduction of fixing every issue on the assets of
// one criticality level.
type Reduction struct {
	Criticality string
	Assets      int64
	Issues      int64
	Points      float64
	// Share is the level's part of all points, in percent.
	Share float64
	// Gain is how many score points fixing them would add (from Raw).
	Gain float64
}

// Reductions returns the risk reduction by asset criticality, most
// critical first, for every level (zero rows included).
func Reductions(total Sums, levels []LevelSums) []Reduction {
	byLevel := map[string]Sums{}
	for _, l := range levels {
		cur := byLevel[l.Criticality]
		cur.Add(l.Sums)
		byLevel[l.Criticality] = cur
	}
	var all float64
	for _, p := range total.Points {
		all += p
	}
	base := Compute(total).Raw
	out := make([]Reduction, 0, 4)
	for _, lvl := range Criticalities() {
		ls := byLevel[lvl]
		r := Reduction{Criticality: lvl, Assets: ls.Assets}
		for i := range ls.Points {
			r.Points += ls.Points[i]
			r.Issues += ls.Issues[i]
		}
		if all > 0 {
			r.Share = math.Round(r.Points*1000/all) / 10
		}
		if r.Points > 0 {
			after := total.Minus(ls)
			after.Assets = total.Assets
			r.Gain = round2(Compute(after).Raw - base)
		}
		r.Points = round2(r.Points)
		out = append(out, r)
	}
	return out
}

// Schedule is how often an organization's posture is recomputed.
type Schedule string

// Schedules.
const (
	ScheduleManual Schedule = "manual"
	ScheduleHourly Schedule = "1h"
	Schedule6h     Schedule = "6h"
	ScheduleDaily  Schedule = "24h"
	// DefaultSchedule applies until an administrator picks another.
	DefaultSchedule = Schedule6h
)

// Schedules returns the valid schedules.
func Schedules() []Schedule {
	return []Schedule{ScheduleManual, ScheduleHourly, Schedule6h, ScheduleDaily}
}

// Valid reports whether s is a known schedule.
func (s Schedule) Valid() bool {
	for _, x := range Schedules() {
		if x == s {
			return true
		}
	}
	return false
}
