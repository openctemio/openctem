package webendpoint

import "testing"

func linkedTestEndpoints() []*Endpoint {
	return []*Endpoint{
		{Method: "GET", PathTemplate: "/login", InScope: true, State: "active"},
		{Method: "POST", PathTemplate: "/login", InScope: true, State: "active"},
	}
}

func findingsAt(l PathLevel, method string) (int, string) {
	for _, e := range l.Endpoints {
		if e.Endpoint.Method == method {
			return e.Findings, e.TopSeverity
		}
	}
	return -1, ""
}

// A finding linked to an endpoint counts at that method only; one with no
// link keeps the template mapping and counts at every method.
func TestBuildPathLevel_LinkedFindingCountsAtItsMethod(t *testing.T) {
	fs := []PathFinding{
		{LocationKey: "url:https://a.test/login", Severity: "high", Count: 1, Template: "/login", Method: "POST"},
		{LocationKey: "url:https://a.test/login", Severity: "low", Count: 2},
	}
	l := BuildPathLevel(linkedTestEndpoints(), fs, "https://a.test", false, PathQuery{Path: "/", Here: false, Page: 1, PerPage: 50})
	if n, top := findingsAt(l, "POST"); n != 3 || top != "high" {
		t.Errorf("POST = %d/%s, want 3/high (linked + unlinked)", n, top)
	}
	if n, top := findingsAt(l, "GET"); n != 2 || top != "low" {
		t.Errorf("GET = %d/%s, want 2/low (the unlinked ones only)", n, top)
	}
	if l.Totals.Findings != 3 {
		t.Errorf("total = %d, want 3 (no double count)", l.Totals.Findings)
	}
}

// With every finding linked, the other method shows none: the exact mapping.
func TestBuildPathLevel_AllLinkedIsExact(t *testing.T) {
	fs := []PathFinding{{LocationKey: "url:https://a.test/login", Severity: "high", Count: 1, Template: "/login", Method: "POST"}}
	l := BuildPathLevel(linkedTestEndpoints(), fs, "https://a.test", false, PathQuery{Path: "/", Page: 1, PerPage: 50})
	if n, _ := findingsAt(l, "GET"); n != 0 {
		t.Errorf("GET = %d, want 0", n)
	}
	if n, _ := findingsAt(l, "POST"); n != 1 {
		t.Errorf("POST = %d, want 1", n)
	}
}

func TestNodeFindings_LinkedUsesEndpointTemplate(t *testing.T) {
	rows := []FindingRow{
		{ID: "1", Title: "linked", Severity: "high", Status: "open", LocationKey: "", Template: "/items/{int}", Method: "GET"},
		{ID: "2", Title: "other", Severity: "low", Status: "open", LocationKey: "url:https://a.test/items/5"},
		{ID: "3", Title: "elsewhere", Severity: "low", Status: "open", Template: "/login", Method: "POST"},
	}
	got, total := NodeFindings(rows, "https://a.test", "/items/{int}")
	if total != 2 || len(got) != 2 || got[0].ID != "1" || got[0].Method != "GET" {
		t.Fatalf("got %+v total %d", got, total)
	}
}
