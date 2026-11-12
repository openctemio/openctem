package report

// Methodology checklist coverage in reports: what each checklist the
// campaign ran covered, per checklist and per section, and the items that
// failed. Tester notes are internal and never reach a report.

// ChecklistData is one checklist a campaign ran.
type ChecklistData struct {
	Name            string
	Standard        string
	StandardVersion string
	Version         int
	Counts          ChecklistCounts
	Sections        []ChecklistSectionData
	FailedItems     []ChecklistItemData
}

// ChecklistCounts counts item results.
type ChecklistCounts struct {
	Total         int
	Passed        int
	Failed        int
	NotApplicable int
	Untested      int
}

// Tested is the number of items with a result.
func (c ChecklistCounts) Tested() int { return c.Total - c.Untested }

// Coverage is the share of items with a result, 0-100, one decimal.
func (c ChecklistCounts) Coverage() float64 {
	if c.Total == 0 {
		return 0
	}
	return float64(c.Tested()*1000/c.Total) / 10
}

func (c *ChecklistCounts) add(o ChecklistCounts) {
	c.Total += o.Total
	c.Passed += o.Passed
	c.Failed += o.Failed
	c.NotApplicable += o.NotApplicable
	c.Untested += o.Untested
}

// ChecklistSectionData is the coverage of one section.
type ChecklistSectionData struct {
	ID     string
	Title  string
	Counts ChecklistCounts
}

// ChecklistItemData is a failed checklist item.
type ChecklistItemData struct {
	ID       string
	Title    string
	Section  string
	Severity string
}

func countsData(c ChecklistCounts) map[string]any {
	return map[string]any{
		"total": c.Total, "passed": c.Passed, "failed": c.Failed, "not_applicable": c.NotApplicable,
		"untested": c.Untested, "tested": c.Tested(), "coverage": c.Coverage(),
	}
}

func withCounts(m map[string]any, c ChecklistCounts) map[string]any {
	for k, v := range countsData(c) {
		m[k] = v
	}
	return m
}

// checklistTemplateData is the checklist part of TemplateData.
func checklistTemplateData(in ReportInput, lang string) map[string]any {
	lists := make([]map[string]any, 0, len(in.Checklists))
	sections := []map[string]any{}
	failed := []map[string]any{}
	var total ChecklistCounts
	for _, c := range in.Checklists {
		total.add(c.Counts)
		lists = append(lists, withCounts(map[string]any{
			"name": c.Name, "standard": c.Standard, "standard_version": c.StandardVersion,
			"template_version": c.Version, "has_failed": c.Counts.Failed > 0,
		}, c.Counts))
		for _, s := range c.Sections {
			sections = append(sections, withCounts(map[string]any{"checklist": c.Name, "id": s.ID, "title": s.Title}, s.Counts))
		}
		for _, it := range c.FailedItems {
			failed = append(failed, map[string]any{
				"checklist": c.Name, "section": it.Section, "id": it.ID, "title": it.Title,
				"severity": it.Severity, "severity_label": label(lang, it.Severity, it.Severity),
			})
		}
	}
	return map[string]any{
		"checklists":             lists,
		"checklist_sections":     sections,
		"checklist_failed_items": failed,
		"checklist_summary":      countsData(total),
		"has_checklists":         len(lists) > 0,
		"has_checklist_failures": len(failed) > 0,
	}
}

// sampleChecklists is the checklist part of the sample report data.
func sampleChecklists() []ChecklistData {
	return []ChecklistData{{
		Name: "OWASP Web Security Testing Guide", Standard: "OWASP WSTG", StandardVersion: "4.2", Version: 1,
		Counts: ChecklistCounts{Total: 12, Passed: 7, Failed: 2, NotApplicable: 1, Untested: 2},
		Sections: []ChecklistSectionData{
			{ID: "WSTG-ATHN", Title: "Authentication Testing", Counts: ChecklistCounts{Total: 6, Passed: 4, Failed: 1, Untested: 1}},
			{ID: "WSTG-INPV", Title: "Input Validation Testing", Counts: ChecklistCounts{Total: 6, Passed: 3, Failed: 1, NotApplicable: 1, Untested: 1}},
		},
		FailedItems: []ChecklistItemData{
			{ID: "WSTG-ATHN-03", Title: "Testing for Weak Lock Out Mechanism", Section: "Authentication Testing", Severity: "medium"},
			{ID: "WSTG-INPV-05", Title: "Testing for SQL Injection", Section: "Input Validation Testing", Severity: "critical"},
		},
	}}
}
