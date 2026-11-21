package webendpoint

import (
	"fmt"
	"testing"
	"time"
)

func ep(method, tmpl string, mut ...func(*Endpoint)) *Endpoint {
	e := &Endpoint{Method: method, PathTemplate: tmpl, State: StateActive, InScope: true, LastStatus: 200}
	for _, m := range mut {
		m(e)
	}
	return e
}

func treeFixture() []*Endpoint {
	return []*Endpoint{
		ep("GET", "/"),
		ep("GET", "/login"),
		ep("POST", "/login"),
		ep("GET", "/api/v1/users"),
		ep("POST", "/api/v1/users"),
		ep("GET", "/api/v1/users/{int}"),
		ep("DELETE", "/api/v1/users/{int}"),
		ep("GET", "/api/v1/users/{int}/orders"),
		ep("GET", "/api/v2/health"),
		ep("GET", "/admin/console", func(e *Endpoint) { e.InScope, e.LastStatus = false, 403 }),
		ep("GET", "/static/app.css", func(e *Endpoint) { e.ContentType = "text/css" }),
		ep("GET", "/static/logo.png"),
		ep("GET", "/static/app.js", func(e *Endpoint) { e.ContentType = "application/javascript" }),
		ep("GET", "/old/page", func(e *Endpoint) { e.State = StateGone }),
	}
}

func folderByName(l PathLevel, name string) *PathFolder {
	for i := range l.Folders {
		if l.Folders[i].Name == name {
			return &l.Folders[i]
		}
	}
	return nil
}

func TestPathQueryValidate(t *testing.T) {
	for _, bad := range []PathQuery{
		{Path: "api"}, {Path: "/api/"}, {Path: "/a//b"}, {Path: "/a?b"}, {Path: "/a#"}, {Path: "/a\x00"},
		{Scope: "maybe"}, {Methods: []string{"FETCH ME"}}, {PerPage: 101}, {PerPage: -1},
		{Search: string(make([]byte, MaxPathSearchBytes+1))},
	} {
		q := bad
		if err := q.Validate(); err == nil {
			t.Errorf("Validate(%+v) = nil, want an error", bad)
		}
	}
	q := PathQuery{Methods: []string{"get"}}
	if err := q.Validate(); err != nil || q.Path != "/" || q.Page != 1 || q.Methods[0] != "GET" {
		t.Fatalf("Validate defaults = %+v %v", q, err)
	}
}

func TestBuildPathLevel_RootFoldersAndCounts(t *testing.T) {
	fs := []PathFinding{
		{LocationKey: "url:https://shop.example.com/api/v1/users/42", Severity: "high", Count: 2},
		{LocationKey: "url:https://shop.example.com/api/v1/users/7/orders", Severity: "medium", Count: 1},
		{LocationKey: "url:https://shop.example.com/.git/config", Severity: "critical", Count: 1}, // no endpoint records it
		{LocationKey: "url:https://other.example.com/api/v1/users", Severity: "low", Count: 1},    // another origin
		{LocationKey: "net:443/tcp", Severity: "medium", Count: 3},                                // no path
	}
	l := BuildPathLevel(treeFixture(), fs, "https://shop.example.com", false, PathQuery{Path: "/", PerPage: 50, Page: 1})
	if l.Totals.Recorded != 14 {
		t.Errorf("recorded = %d", l.Totals.Recorded)
	}
	// Gone is hidden by default, and counted as hidden, never dropped silently.
	if l.Totals.Endpoints != 13 || l.Totals.Hidden != 1 {
		t.Errorf("endpoints/hidden = %d/%d", l.Totals.Endpoints, l.Totals.Hidden)
	}
	if l.Totals.OriginFindings != 4 || l.Totals.Unrecorded != 1 || l.Totals.Findings != 4 || l.Totals.TopSeverity != "critical" {
		t.Errorf("findings totals = %+v", l.Totals)
	}
	api := folderByName(l, "api")
	if api == nil || api.Endpoints != 6 || api.Findings != 3 || api.TopSeverity != "high" || !api.HasFolders {
		t.Fatalf("api folder = %+v", api)
	}
	git := folderByName(l, ".git")
	if git == nil || git.Endpoints != 0 || git.Findings != 1 || git.TopSeverity != "critical" {
		t.Fatalf(".git folder (finding only) = %+v", git)
	}
	admin := folderByName(l, "admin")
	if admin == nil || admin.OutOfScope != 1 || admin.Endpoints != 1 {
		t.Fatalf("out-of-scope folder must stay listed: %+v", admin)
	}
	if folderByName(l, "old") != nil {
		t.Errorf("a folder holding only gone endpoints is listed")
	}
	// The page lists everything under the prefix, sorted by path then method.
	if l.EndpointTotal != 13 || l.Endpoints[0].Endpoint.PathTemplate != "/" {
		t.Errorf("page = %d first %q", l.EndpointTotal, l.Endpoints[0].Endpoint.PathTemplate)
	}
}

func TestBuildPathLevel_ParamFolderAndMethodBlindFindings(t *testing.T) {
	fs := []PathFinding{{LocationKey: "url:https://shop.example.com/api/v1/users/42", Severity: "high", Count: 2}}
	l := BuildPathLevel(treeFixture(), fs, "https://shop.example.com", false, PathQuery{Path: "/api/v1/users", PerPage: 50, Page: 1, Here: true})
	p := folderByName(l, "{int}")
	if p == nil || !p.Param || p.Path != "/api/v1/users/{int}" || p.Endpoints != 3 || p.Findings != 2 || !p.HasFolders {
		t.Fatalf("{int} node = %+v", p)
	}
	// Here: only the node's own template (GET and POST /api/v1/users).
	if l.EndpointTotal != 2 || l.Endpoints[0].Endpoint.PathTemplate != "/api/v1/users" {
		t.Errorf("here = %d %+v", l.EndpointTotal, l.Endpoints)
	}
	l = BuildPathLevel(treeFixture(), fs, "https://shop.example.com", false, PathQuery{Path: "/api/v1/users/{int}", PerPage: 50, Page: 1, Here: true})
	if l.EndpointTotal != 2 || l.Endpoints[0].Endpoint.PathTemplate != "/api/v1/users/{int}" || l.Endpoints[0].Findings != 2 {
		t.Fatalf("here endpoints = %+v", l.Endpoints)
	}
	if o := folderByName(l, "orders"); o == nil || o.HasFolders || o.Endpoints != 1 {
		t.Fatalf("orders leaf = %+v", o)
	}
	// Both methods of /api/v1/users/{int} carry the path's findings; the
	// folder counts them once.
	l = BuildPathLevel(treeFixture(), fs, "https://shop.example.com", false, PathQuery{Path: "/api/v1", PerPage: 50, Page: 1})
	n := 0
	for _, e := range l.Endpoints {
		if e.Endpoint.PathTemplate == "/api/v1/users/{int}" {
			if e.Findings != 2 || e.TopSeverity != "high" {
				t.Errorf("%s %s findings = %d %q", e.Endpoint.Method, e.Endpoint.PathTemplate, e.Findings, e.TopSeverity)
			}
			n++
		}
	}
	if n != 2 || l.Totals.Findings != 2 || folderByName(l, "users").Findings != 2 {
		t.Errorf("method-blind mapping: rows %d totals %d", n, l.Totals.Findings)
	}
}

func TestBuildPathLevel_Filters(t *testing.T) {
	fs := []PathFinding{{LocationKey: "url:https://shop.example.com/login", Severity: "medium", Count: 1}}
	base := PathQuery{Path: "/", PerPage: 50, Page: 1}
	cases := []struct {
		name   string
		mod    func(*PathQuery)
		shown  int
		hidden int
	}{
		{"static hidden, scripts kept", func(q *PathQuery) { q.HideStatic = true }, 11, 3},
		{"4xx hidden", func(q *PathQuery) { q.Hide4xx = true }, 12, 2},
		{"with findings", func(q *PathQuery) { q.WithFindings = true }, 2, 12},
		{"out of scope only", func(q *PathQuery) { q.Scope = PathScopeOut }, 1, 13},
		{"in scope only", func(q *PathQuery) { q.Scope = PathScopeIn }, 12, 2},
		{"methods", func(q *PathQuery) { q.Methods = []string{"POST", "DELETE"} }, 3, 11},
		{"gone included", func(q *PathQuery) { q.IncludeGone = true }, 14, 0},
		{"search, any case", func(q *PathQuery) { q.Search = "USERS" }, 5, 0},
	}
	for _, c := range cases {
		q := base
		c.mod(&q)
		l := BuildPathLevel(treeFixture(), fs, "https://shop.example.com", false, q)
		if l.Totals.Endpoints != c.shown || l.Totals.Hidden != c.hidden {
			t.Errorf("%s: shown/hidden = %d/%d, want %d/%d", c.name, l.Totals.Endpoints, l.Totals.Hidden, c.shown, c.hidden)
		}
	}
}

func TestBuildPathLevel_PagingAndFolderCap(t *testing.T) {
	eps := make([]*Endpoint, 0, MaxPathFolders+10)
	for i := range MaxPathFolders + 10 {
		eps = append(eps, ep("GET", fmt.Sprintf("/f%04d/x", i)))
	}
	l := BuildPathLevel(eps, nil, "https://shop.example.com", false, PathQuery{Path: "/", PerPage: 0, Page: 1})
	if len(l.Folders) != MaxPathFolders || !l.FoldersTruncated || l.Endpoints != nil || l.EndpointTotal != len(eps) {
		t.Fatalf("folders %d truncated %v endpoints %d total %d", len(l.Folders), l.FoldersTruncated, len(l.Endpoints), l.EndpointTotal)
	}
	l = BuildPathLevel(eps, nil, "https://shop.example.com", false, PathQuery{Path: "/", PerPage: 100, Page: 6})
	if len(l.Endpoints) != 10 || l.Endpoints[0].Endpoint.PathTemplate != "/f0500/x" {
		t.Fatalf("last page = %d", len(l.Endpoints))
	}
}

func TestIsStatic(t *testing.T) {
	for tmpl, want := range map[string]bool{
		"/a/b.css": true, "/img/x.PNG": true, "/f/a.woff2": true, "/d/r.pdf": true,
		"/app.js": false, "/app.js.map": false, "/api/users": false, "/style.css.php": false,
	} {
		if got := IsStatic(&Endpoint{PathTemplate: tmpl}); got != want {
			t.Errorf("IsStatic(%s) = %v", tmpl, got)
		}
	}
	if !IsStatic(&Endpoint{PathTemplate: "/x", ContentType: "image/svg+xml"}) {
		t.Error("image content type not static")
	}
}

// The tree of a full origin (the 5,000 active endpoints cap, plus gone rows)
// with a finding at every tenth path is built well inside a request budget.
func TestBuildPathLevel_FullOriginBudget(t *testing.T) {
	eps := make([]*Endpoint, 0, PathLoadLimit)
	fs := make([]PathFinding, 0, PathLoadLimit/10)
	for i := range PathLoadLimit {
		tmpl := fmt.Sprintf("/area%02d/section%02d/item%03d/{int}", i%20, (i/20)%25, i/500)
		eps = append(eps, ep([]string{"GET", "POST", "PUT", "DELETE"}[i%4], tmpl))
		if i%10 == 0 {
			fs = append(fs, PathFinding{LocationKey: "url:https://shop.example.com" + tmpl[:len(tmpl)-5] + "/9", Severity: "high", Count: 1})
		}
	}
	start := time.Now()
	const runs = 20
	for range runs {
		_ = BuildPathLevel(eps, fs, "https://shop.example.com", false, PathQuery{Path: "/area03", PerPage: 50, Page: 1, HideStatic: true})
	}
	per := time.Since(start) / runs
	t.Logf("BuildPathLevel over %d endpoints and %d finding groups: %s per call", len(eps), len(fs), per)
	if per > 250*time.Millisecond {
		t.Errorf("BuildPathLevel took %s per call", per)
	}
}

func TestNodeFindings(t *testing.T) {
	rows := []FindingRow{
		{ID: "1", Title: "IDOR", Severity: "medium", Status: "new", LocationKey: "url:https://shop.example.com/api/users/42"},
		{ID: "2", Title: "SQLi", Severity: "critical", Status: "confirmed", LocationKey: "url:https://shop.example.com/api/users/7"},
		{ID: "3", Title: "Other origin", Severity: "high", Status: "new", LocationKey: "url:https://other.example.com/api/users/1"},
		{ID: "4", Title: "Below", Severity: "high", Status: "new", LocationKey: "url:https://shop.example.com/api/users/1/orders"},
		{ID: "5", Title: "Token", Severity: "low", Status: "new", LocationKey: "url:https://shop.example.com/reset/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
	}
	got, total := NodeFindings(rows, "https://shop.example.com", "/api/users/{int}")
	if total != 2 || got[0].ID != "2" || got[1].ID != "1" || got[0].Path != "/api/users/7" {
		t.Fatalf("NodeFindings = %d %+v", total, got)
	}
	// A token-like segment never comes back concrete.
	got, _ = NodeFindings(rows, "https://shop.example.com", "/reset/{hex}")
	if len(got) != 1 || got[0].Path != "/reset/{hex}" {
		t.Fatalf("masked path = %+v", got)
	}
	q := PathQuery{Findings: true}
	if err := q.Validate(); err == nil {
		t.Error("findings without here accepted")
	}
}
