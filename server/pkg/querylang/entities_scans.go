package querylang

import (
	"github.com/openctemio/openctem/server/pkg/domain/permission"
	"github.com/openctemio/openctem/server/pkg/domain/scan"
	"github.com/openctemio/openctem/server/pkg/filterspec"
)

// Field names the scans entity declares more than once.
const (
	scanFieldStatus    = "status"
	scanFieldCreatedAt = "created_at"
	scanFieldText      = "text_search"
)

// scanQueryFields is the scans list registry (with the archived and ad_hoc
// fields the server's own rules use) plus the text search field.
var scanQueryFields = func() *filterspec.Registry {
	reg, err := scan.ListFields.Extend(textSearchField(scan.Fields))
	if err != nil {
		panic(err)
	}
	return reg
}()

// Scans is the scans entity: the tenant's saved scans, as GET /scans lists
// them. A scan is tenant configuration, so the data scope does not narrow it.
var Scans = MustEntity(EntityDef{
	Name: "scans", Noun: "scans", Permission: permission.ScansRead.String(),
	Registry:  scanQueryFields,
	Internal:  []string{"archived", "ad_hoc", scanFieldText},
	TextField: scanFieldText,
	Dimensions: []string{
		scanFieldStatus, "scan_type", "schedule_type", "sensor_preference", "origin", "last_run_status",
	},
	Measures: []string{"total_runs", "failed_runs"},
	Times:    []string{scanFieldCreatedAt, "last_run_at", "next_run_at"},
	Mandatory: []Mandatory{
		{Leaf: &filterspec.Leaf{Field: "archived", Op: filterspec.OpEq, Values: []any{false}},
			Why: "archived scans are left out"},
		{Leaf: &filterspec.Leaf{Field: "ad_hoc", Op: filterspec.OpEq, Values: []any{false}},
			Why: "quick scans that were never saved are left out"},
	},
})

// The scans entity joins the others here, not in the shared map literal.
func init() { entities[Scans.Name] = Scans }
