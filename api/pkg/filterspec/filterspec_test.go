package filterspec

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var fixedNow = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

func testOpts() Options { return Options{Now: func() time.Time { return fixedNow }} }

// testRegistry is a findings-like registry covering every type and operator.
func testRegistry(t testing.TB) *Registry {
	t.Helper()
	reg, err := NewRegistry(Registry{
		Name:             "findings",
		TenantSQL:        "f.tenant_id",
		ScopeAssetSQL:    "f.asset_id",
		IDSQL:            "f.id",
		DefaultSort:      []SortKey{{Field: "severity", Desc: true}},
		MemberVisibility: "(f.source <> 'pentest' OR f.campaign_id IN (SELECT campaign_id FROM members WHERE user_id = {user} AND tenant_id = {tenant}))",
		Search:           &Search{Template: `(f.title ILIKE {arg} ESCAPE '\' OR f.rule_id ILIKE {arg} ESCAPE '\')`, Pattern: true},
		Aliases: map[string]Alias{
			"severities":       {To: "severity"},
			"exclude_statuses": {To: "status_not"},
			"epss_min":         {To: "epss_score_gte"},
			"search":           {To: "q"},
			"assigned_to_me": {To: "related_to", Value: func(v string) (string, bool) {
				if v == "true" || v == "1" {
					return "me", true
				}
				return "", false
			}},
		},
	},
		Field{Name: "severity", Type: TypeEnum, Enum: []string{"critical", "high", "medium", "low", "info"}, Ops: []Op{OpIn, OpNotIn}, SQL: "f.severity", Sortable: true, SortSQL: "f.severity_rank", Indexed: true},
		Field{Name: "status", Type: TypeEnum, Enum: []string{"new", "confirmed", "resolved", "false_positive"}, Ops: []Op{OpIn, OpNotIn}, SQL: "f.status", Indexed: true},
		Field{Name: "asset_id", Type: TypeID, Ops: []Op{OpIn, OpNotIn}, SQL: "f.asset_id", MaxValuesDocument: 500, Indexed: true},
		Field{Name: "epss_score", Type: TypeNumber, Ops: []Op{OpGte, OpLte, OpGt, OpLt}, SQL: "f.epss_score", Nullable: true, Sortable: true},
		Field{Name: "network_port", Type: TypeInt, Ops: []Op{OpIn, OpNotIn, OpGte, OpLte}, SQL: "f.port"},
		Field{Name: "is_in_kev", Type: TypeBool, Ops: []Op{OpEq}, SQL: "f.is_in_kev"},
		Field{Name: "last_seen_at", Type: TypeTime, Ops: []Op{OpGte, OpLte, OpGt, OpLt}, SQL: "f.last_seen_at", Sortable: true},
		Field{Name: "rule_id", Type: TypeString, Ops: []Op{OpIn}, SQL: "f.rule_id"},
		Field{Name: "file_path", Type: TypeString, Ops: []Op{OpContains}, SQL: "f.file_path"},
		Field{Name: "assigned_to", Type: TypeID, Ops: []Op{OpIn, OpIsNull}, SQL: "f.assigned_to", Nullable: true},
		Field{Name: "asset_tag", Type: TypeString, Ops: []Op{OpIn, OpNotIn}, SQL: "a.tags",
			Templates: map[Op]string{
				OpIn:    "EXISTS (SELECT 1 FROM assets a WHERE a.id = f.asset_id AND a.tenant_id = f.tenant_id AND a.tags && {arg})",
				OpNotIn: "NOT EXISTS (SELECT 1 FROM assets a WHERE a.id = f.asset_id AND a.tenant_id = f.tenant_id AND a.tags && {arg})",
			}},
		Field{Name: "related_to", Type: TypeEnum, Enum: []string{"me"}, Ops: []Op{OpEq}, SQL: "f.assigned_to",
			Templates: map[Op]string{OpEq: "f.assigned_to = {user}"}},
		Field{Name: "pentest_note", Type: TypeString, Ops: []Op{OpIn}, SQL: "f.pentest_note", Permission: "pentest:read", Sortable: true},
	)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return reg
}

var (
	tenantA   = shared.MustIDFromString("11111111-1111-1111-1111-111111111111")
	tenantB   = shared.MustIDFromString("22222222-2222-2222-2222-222222222222")
	userA     = shared.MustIDFromString("33333333-3333-3333-3333-333333333333")
	adminUser = shared.MustIDFromString("55555555-5555-5555-5555-555555555555")
)

func adminActor(t testing.TB) Actor {
	t.Helper()
	a, err := UserActor(UserActorInput{TenantID: tenantA, UserID: adminUser, IsAdmin: true, Has: func(string) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func memberActor(t testing.TB) Actor {
	t.Helper()
	a, err := UserActor(UserActorInput{TenantID: tenantA, UserID: userA, Scope: &shared.DataScope{TenantID: tenantA, UserID: userA}})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func mustParse(t *testing.T, raw string, opts Options) *Spec {
	t.Helper()
	q, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseValues(q, testRegistry(t), opts)
	if err != nil {
		t.Fatalf("ParseValues(%q): %v", raw, err)
	}
	return s
}

func parseErr(t *testing.T, raw string, opts Options) *Error {
	t.Helper()
	q, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseValues(q, testRegistry(t), opts)
	fe, ok := AsError(err)
	if !ok {
		t.Fatalf("ParseValues(%q): want *Error, got %v", raw, err)
	}
	return fe
}

func TestRegistryRejectsBadFields(t *testing.T) {
	base := Registry{Name: "x", TenantSQL: "t.tenant_id", ScopeAssetSQL: "t.asset_id", IDSQL: "t.id"}
	cases := map[string]Field{
		"suffix name":         {Name: "score_gte", Type: TypeNumber, Ops: []Op{OpGte}, SQL: "t.s"},
		"not suffix":          {Name: "status_not", Type: TypeEnum, Enum: []string{"a"}, Ops: []Op{OpIn}, SQL: "t.s"},
		"camel case":          {Name: "isInKev", Type: TypeBool, Ops: []Op{OpEq}, SQL: "t.k"},
		"reserved":            {Name: "sort", Type: TypeString, Ops: []Op{OpIn}, SQL: "t.s"},
		"catch-all":           {Name: "filters", Type: TypeString, Ops: []Op{OpIn}, SQL: "t.s"},
		"enum without values": {Name: "level", Type: TypeEnum, Ops: []Op{OpIn}, SQL: "t.l"},
		"range on string":     {Name: "name", Type: TypeString, Ops: []Op{OpGte}, SQL: "t.n"},
		"is_null not null":    {Name: "owner", Type: TypeID, Ops: []Op{OpIsNull}, SQL: "t.o"},
		"contains on id":      {Name: "owner", Type: TypeID, Ops: []Op{OpContains}, SQL: "t.o"},
		"template no arg":     {Name: "tag", Type: TypeString, Ops: []Op{OpIn}, SQL: "t.t", Templates: map[Op]string{OpIn: "t.tags && ARRAY['x']"}},
		"no sql":              {Name: "tag", Type: TypeString, Ops: []Op{OpIn}},
		"too many values":     {Name: "tag", Type: TypeString, Ops: []Op{OpIn}, SQL: "t.t", MaxValues: 1000},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewRegistry(base, f); err == nil {
				t.Fatalf("want error for %+v", f)
			}
		})
	}
	if _, err := NewRegistry(Registry{Name: "x", TenantSQL: "t.tenant_id", IDSQL: "t.id"}); err == nil {
		t.Fatal("a registry with no scope column and no Unscoped reason must be rejected")
	}
	if _, err := NewRegistry(Registry{Name: "x", TenantSQL: "t.tenant_id", IDSQL: "t.id", Unscoped: "tenant settings"}); err != nil {
		t.Fatalf("an explained unscoped registry is valid: %v", err)
	}
	bad := base
	bad.Aliases = map[string]Alias{"old": {To: "nope"}}
	if _, err := NewRegistry(bad, Field{Name: "tag", Type: TypeString, Ops: []Op{OpIn}, SQL: "t.t"}); err == nil {
		t.Fatal("alias to an unknown param must be rejected")
	}
}

func TestParseValuesBasics(t *testing.T) {
	s := mustParse(t, "severity=critical,HIGH&severity=low&status_not=resolved&epss_score_gte=0.1&is_in_kev=true&last_seen_at_gte=-P30D&network_port=443,8443&q=log4j&sort=-severity,last_seen_at&page=2&per_page=500", testOpts())
	if s.Q != "log4j" || s.Page != 2 || s.PerPage != 100 {
		t.Fatalf("q/page/per_page: %+v", s)
	}
	if len(s.Sort) != 2 || !s.Sort[0].Desc || s.Sort[1].Field != "last_seen_at" {
		t.Fatalf("sort: %+v", s.Sort)
	}
	got := map[string]*Leaf{}
	for _, l := range s.Leaves() {
		got[l.Field+":"+string(l.Op)] = l
	}
	if l := got["severity:in"]; l == nil || len(l.Values) != 3 || l.Values[1] != "high" {
		t.Fatalf("severity: %+v", l)
	}
	if l := got["status:not_in"]; l == nil || l.Values[0] != "resolved" {
		t.Fatalf("status_not: %+v", l)
	}
	if l := got["epss_score:gte"]; l == nil || l.Values[0] != 0.1 {
		t.Fatalf("epss: %+v", l)
	}
	if l := got["is_in_kev:eq"]; l == nil || l.Values[0] != true {
		t.Fatalf("kev: %+v", l)
	}
	if l := got["last_seen_at:gte"]; l == nil || !l.Values[0].(time.Time).Equal(fixedNow.Add(-30*24*time.Hour)) {
		t.Fatalf("last_seen: %+v", l)
	}
	if l := got["network_port:in"]; l == nil || l.Values[0] != int64(443) {
		t.Fatalf("port: %+v", l)
	}
}

func TestParseValuesDates(t *testing.T) {
	s := mustParse(t, "last_seen_at_gte=2026-09-01&last_seen_at_lte=2026-09-30", testOpts())
	for _, l := range s.Leaves() {
		v := l.Values[0].(time.Time)
		switch l.Op {
		case OpGte:
			if !v.Equal(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)) {
				t.Fatalf("gte date: %v", v)
			}
		case OpLte:
			if v.Day() != 30 || v.Hour() != 23 {
				t.Fatalf("lte date should be end of day: %v", v)
			}
		}
	}
	for _, bad := range []string{"-P", "-PT", "-P0D", "P30D", "-P99999W", "yesterday", "2026-13-01"} {
		fe := parseErr(t, "last_seen_at_gte="+url.QueryEscape(bad), testOpts())
		if fe.Details[0].Param != "last_seen_at_gte" {
			t.Fatalf("%q: %+v", bad, fe.Details)
		}
	}
}

func TestParseValuesRejectsBadValues(t *testing.T) {
	cases := map[string]string{
		"severity=urgent":            "severity",
		"is_in_kev=yes":              "is_in_kev",
		"epss_score_gte=high":        "epss_score_gte",
		"epss_score_gte=NaN":         "epss_score_gte",
		"epss_score_gte=1,2":         "epss_score_gte",
		"asset_id=not-a-uuid":        "asset_id",
		"network_port=80x":           "network_port",
		"sort=-nope":                 "sort",
		"sort=severity,severity":     "sort",
		"page=abc":                   "page",
		"page=0":                     "page",
		"rule_id=a%00b":              "rule_id",
		"q=a%01b":                    "q",
		"assigned_to_null=maybe":     "assigned_to_null",
		"page=101&per_page=100":      "page",
		"file_path_contains=" + long: "file_path_contains",
	}
	for raw, param := range cases {
		t.Run(raw[:min(len(raw), 30)], func(t *testing.T) {
			fe := parseErr(t, raw, testOpts())
			if fe.Details[0].Param != param {
				t.Fatalf("want param %q, got %+v", param, fe.Details)
			}
			api := fe.APIError()
			if api.Status != http.StatusBadRequest || api.Code != apierror.CodeInvalidFilter {
				t.Fatalf("api error: %+v", api)
			}
		})
	}
}

var long = strings.Repeat("a", MaxValueLen+1)

func TestParseValuesListCapIs400NotTruncation(t *testing.T) {
	ids := make([]string, MaxValues+1)
	for i := range ids {
		ids[i] = "rule" + strings.Repeat("x", i%5) + string(rune('a'+i%26))
	}
	fe := parseErr(t, "rule_id="+strings.Join(ids, ","), testOpts())
	if !strings.Contains(fe.Details[0].Reason, "too many values") {
		t.Fatalf("%+v", fe.Details)
	}
}

func TestUnknownParamWarnAndStrict(t *testing.T) {
	s := mustParse(t, "severity=high&source_id=abc&is_kev=true&group_by=cve_id", Options{Extra: []string{"group_by"}})
	if strings.Join(s.UnknownParams, ",") != "is_kev,source_id" {
		t.Fatalf("warn mode should record unknown params, got %v", s.UnknownParams)
	}
	fe := parseErr(t, "severity=high&source_id=abc", Options{Unknown: UnknownStrict})
	if fe.Details[0].Param != "source_id" || fe.Details[0].Reason != "unknown parameter" {
		t.Fatalf("strict: %+v", fe.Details)
	}
	// A known field with an operator it does not allow is unknown too.
	fe = parseErr(t, "is_in_kev_not=true", Options{Unknown: UnknownStrict})
	if fe.Details[0].Param != "is_in_kev_not" {
		t.Fatalf("%+v", fe.Details)
	}
	// Bad values for known params are 400 even in warn mode.
	parseErr(t, "severity=urgent", Options{Unknown: UnknownWarn})
}

func TestAliases(t *testing.T) {
	s := mustParse(t, "severities=high&exclude_statuses=resolved&epss_min=0.5&search=x&assigned_to_me=true", testOpts())
	if len(s.AliasesUsed) != 5 {
		t.Fatalf("aliases: %+v", s.AliasesUsed)
	}
	if s.Q != "x" {
		t.Fatalf("search alias: %q", s.Q)
	}
	ops := map[string]Op{}
	for _, l := range s.Leaves() {
		ops[l.Field] = l.Op
	}
	if ops["severity"] != OpIn || ops["status"] != OpNotIn || ops["epss_score"] != OpGte || ops["related_to"] != OpEq {
		t.Fatalf("alias mapping: %v", ops)
	}
	s = mustParse(t, "assigned_to_me=false", testOpts())
	if s.Root != nil {
		t.Fatalf("assigned_to_me=false means no filter, got %+v", s.Root)
	}
}

func TestEmptyValueIsNoFilter(t *testing.T) {
	s := mustParse(t, "severity=&status=,,", testOpts())
	if s.Root != nil {
		t.Fatalf("empty values must not create leaves: %+v", s.Leaves())
	}
}

func TestFreeTextNeverEchoed(t *testing.T) {
	fe := parseErr(t, "file_path_contains="+url.QueryEscape("secret-host.corp\x01"), testOpts())
	if fe.Details[0].Value != "" {
		t.Fatalf("free text echoed: %+v", fe.Details)
	}
	fe = parseErr(t, "severity="+strings.Repeat("z", 150), testOpts())
	if n := len(fe.Details[0].Value); n == 0 || n > 64 {
		t.Fatalf("typed value should be echoed, capped at 64: %d", n)
	}
	b, _ := json.Marshal(fe.APIError().ToResponse())
	if !strings.Contains(string(b), `"code":"INVALID_FILTER"`) || !strings.Contains(string(b), `"param":"severity"`) {
		t.Fatalf("envelope: %s", b)
	}
}

func TestParseDocument(t *testing.T) {
	doc := `{"v":1,"filter":{"all":[
		{"field":"severity","op":"in","value":["critical","high"]},
		{"field":"status","op":"not_in","value":["resolved","false_positive"]},
		{"any":[{"field":"is_in_kev","op":"eq","value":true},{"field":"epss_score","op":"gte","value":0.1}]},
		{"not":{"field":"asset_tag","op":"in","value":["sandbox"]}}
	]},"q":"log4j","sort":["-severity","last_seen_at"],"page":{"page":2,"per_page":50}}`
	s, err := ParseDocument([]byte(doc), testRegistry(t), testOpts())
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Leaves()) != 5 || s.Q != "log4j" || s.Page != 2 || s.PerPage != 50 || len(s.Sort) != 2 {
		t.Fatalf("%+v", s)
	}
	w, err := Compile(s, testRegistry(t), adminActor(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{" OR ", "(NOT COALESCE(", "a.tags && $", "f.title ILIKE $"} {
		if !strings.Contains(w.SQL, want) {
			t.Fatalf("missing %q in %s", want, w.SQL)
		}
	}
}

func TestParseDocumentShorthandEqualsGET(t *testing.T) {
	reg := testRegistry(t)
	doc, err := ParseDocument([]byte(`{"filter":{"severity":["critical","high"],"epss_score_gte":0.1,"status_not":"resolved"}}`), reg, testOpts())
	if err != nil {
		t.Fatal(err)
	}
	get := mustParse(t, "severity=critical,high&epss_score_gte=0.1&status_not=resolved", testOpts())
	wd, _ := Compile(doc, reg, adminActor(t))
	wg, _ := Compile(get, reg, adminActor(t))
	if wd.SQL != wg.SQL {
		t.Fatalf("shorthand and GET compile differently:\n%s\n%s", wd.SQL, wg.SQL)
	}
}

func TestParseDocumentErrors(t *testing.T) {
	deep := `{"filter":{"all":[{"any":[{"not":{"all":[{"field":"severity","op":"in","value":["high"]}]}}]}]}}`
	manyLeaves := `{"filter":{"all":[` + strings.TrimSuffix(strings.Repeat(`{"field":"severity","op":"in","value":["high"]},`, MaxLeaves+1), ",") + `]}}`
	big := `{"q":"` + strings.Repeat("a", MaxBodyBytes) + `"}`
	cases := map[string]struct{ doc, path string }{
		"not json":       {`{`, "$"},
		"array":          {`[]`, "$"},
		"trailing":       {`{} {}`, "$"},
		"version":        {`{"v":2}`, "v"},
		"unknown key":    {`{"filters":{}}`, "filters"},
		"unknown field":  {`{"filter":{"field":"is_kev","op":"eq","value":true}}`, "filter.field"},
		"bad op":         {`{"filter":{"field":"severity","op":"gte","value":"high"}}`, "filter.op"},
		"bad enum":       {`{"filter":{"all":[{"field":"severity","op":"in","value":["urgent"]}]}}`, "filter.all[0].value"},
		"string as bool": {`{"filter":{"field":"is_in_kev","op":"eq","value":"true"}}`, "filter.value"},
		"array for eq":   {`{"filter":{"field":"is_in_kev","op":"eq","value":[true]}}`, "filter.value"},
		"object value":   {`{"filter":{"field":"severity","op":"in","value":{"x":1}}}`, "filter.value"},
		"leaf extra key": {`{"filter":{"field":"severity","op":"in","value":["high"],"sql":"1=1"}}`, "filter.sql"},
		"two groups":     {`{"filter":{"all":[],"any":[]}}`, "filter"},
		"empty all":      {`{"filter":{"all":[]}}`, "filter.all"},
		"deep":           {deep, "filter.all[0].any[0].not"},
		"leaves":         {manyLeaves, "filter.all"},
		"body":           {big, "$"},
		"sort unknown":   {`{"sort":["-nope"]}`, "sort"},
		"sort object":    {`{"sort":{"a":1}}`, "sort"},
		"page zero":      {`{"page":{"page":0}}`, "page.page"},
		"cursor":         {`{"page":{"cursor":"abc"}}`, "page.cursor"},
		"null value":     {`{"filter":{"field":"severity","op":"in","value":null}}`, "filter.value"},
		"weird key":      {`{"filter":{"Sévérité":["high"]}}`, "filter.<invalid>"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseDocument([]byte(c.doc), testRegistry(t), testOpts())
			fe, ok := AsError(err)
			if !ok {
				t.Fatalf("want *Error, got %v", err)
			}
			if fe.Details[0].Path != c.path {
				t.Fatalf("want path %q, got %+v", c.path, fe.Details)
			}
		})
	}
}

func TestDocumentIDListAllows500(t *testing.T) {
	ids := make([]string, 0, 500)
	for i := 0; i < 500; i++ {
		ids = append(ids, `"`+shared.NewID().String()+`"`)
	}
	doc := `{"filter":{"field":"asset_id","op":"in","value":[` + strings.Join(ids, ",") + `]}}`
	if _, err := ParseDocument([]byte(doc), testRegistry(t), testOpts()); err != nil {
		t.Fatalf("500 ids in a document: %v", err)
	}
}

func TestCompileAlwaysTenantFirst(t *testing.T) {
	reg := testRegistry(t)
	s := mustParse(t, "severity=high", testOpts())

	w, err := Compile(s, reg, adminActor(t))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(w.SQL, "f.tenant_id = $1") || w.Args[0] != tenantA.String() {
		t.Fatalf("tenant predicate must come first: %s %v", w.SQL, w.Args)
	}
	if strings.Contains(w.SQL, "user_accessible_assets") {
		t.Fatal("an unrestricted actor gets no scope predicate")
	}

	w, err = Compile(s, reg, memberActor(t))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(w.SQL, "f.tenant_id = $1 AND (f.asset_id IN (SELECT uaa.asset_id FROM user_accessible_assets uaa WHERE uaa.user_id = $2 AND uaa.tenant_id = $3) AND NOT EXISTS (SELECT 1 FROM assets ph WHERE ph.id = f.asset_id") {
		t.Fatalf("restricted actor must get the scope predicate: %s", w.SQL)
	}
	if w.Args[1] != userA.String() || w.Args[2] != tenantA.String() {
		t.Fatalf("scope args: %v", w.Args)
	}

	w, err = Compile(s, reg, SystemActor(tenantA, "test"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(w.SQL, "f.tenant_id = $1") || strings.Contains(w.SQL, "user_accessible_assets") {
		t.Fatalf("system actor keeps the tenant and skips scope: %s", w.SQL)
	}

	if _, err := Compile(s, reg, Actor{}); err == nil {
		t.Fatal("the zero Actor must be rejected")
	}
	if _, err := Compile(s, reg, SystemActor(shared.ID{}, "x")); err == nil {
		t.Fatal("an actor without a tenant must be rejected")
	}
	if _, err := UserActor(UserActorInput{TenantID: tenantA, UserID: userA, Scope: &shared.DataScope{TenantID: tenantB, UserID: userA}}); err == nil {
		t.Fatal("a scope from another tenant must be rejected")
	}
	if _, err := UserActor(UserActorInput{TenantID: tenantA, UserID: adminUser, Scope: &shared.DataScope{TenantID: tenantA, UserID: userA}}); err == nil {
		t.Fatal("a scope of another user must be rejected")
	}
}

func TestMemberVisibilityAndUserTokens(t *testing.T) {
	reg := testRegistry(t)
	s := mustParse(t, "related_to=me", testOpts())

	w, err := Compile(s, reg, memberActor(t))
	if err != nil {
		t.Fatal(err)
	}
	// Tenant $1, scope $2/$3, user bound once ($4) and reused by related_to.
	if !strings.Contains(w.SQL, "user_id = $4::uuid AND tenant_id = $1") || !strings.Contains(w.SQL, "(f.assigned_to = $4::uuid)") {
		t.Fatalf("member visibility / user token: %s", w.SQL)
	}
	if w.Args[3] != userA.String() {
		t.Fatalf("user arg: %v", w.Args)
	}
	assertPlaceholders(t, w, 1)

	// An administrator gets no member rule; the user token still binds.
	w, _ = Compile(s, reg, adminActor(t))
	if strings.Contains(w.SQL, "pentest") || !strings.Contains(w.SQL, "(f.assigned_to = $2::uuid)") {
		t.Fatalf("admin: %s", w.SQL)
	}

	// A user-less key is a member: the rule applies with the zero UUID, so
	// user-relative visibility fails closed; related_to=me is unknown.
	keyActor, _ := UserActor(UserActorInput{TenantID: tenantA})
	w, err = Compile(mustParse(t, "", testOpts()), reg, keyActor)
	if err != nil || !strings.Contains(w.SQL, "pentest") || w.Args[1] != (shared.ID{}).String() {
		t.Fatalf("user-less key: %v %s %v", err, w.SQL, w.Args)
	}
	if _, err := Compile(s, reg, keyActor); err == nil {
		t.Fatal("related_to=me without a user must be rejected")
	}

	// SystemActor skips the member rule and cannot use user tokens.
	w, _ = Compile(mustParse(t, "", testOpts()), reg, SystemActor(tenantA, "t"))
	if strings.Contains(w.SQL, "pentest") {
		t.Fatalf("system actor got the member rule: %s", w.SQL)
	}
	if _, err := Compile(s, reg, SystemActor(tenantA, "t")); err == nil {
		t.Fatal("related_to=me as SystemActor must be rejected")
	}
}

func TestEnumIsCaseInsensitiveAndCanonical(t *testing.T) {
	reg := MustRegistry(Registry{Name: "x", TenantSQL: "t.tenant_id", ScopeAssetSQL: "t.asset_id", IDSQL: "t.id"},
		Field{Name: "priority_class", Type: TypeEnum, Enum: []string{"P0", "P1"}, Ops: []Op{OpIn}, SQL: "t.p"})
	s, err := ParseValues(url.Values{"priority_class": {"p0,P1"}}, reg, testOpts())
	if err != nil {
		t.Fatal(err)
	}
	if v := s.Leaves()[0].Values; v[0] != "P0" || v[1] != "P1" {
		t.Fatalf("enum values must use the registry spelling: %v", v)
	}
}

func TestCompileFromOffsetsPlaceholders(t *testing.T) {
	s := mustParse(t, "severity=high,low&q=x", testOpts())
	w, err := CompileFrom(s, testRegistry(t), memberActor(t), 4)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(w.SQL, "f.tenant_id = $4") || w.NextArg != 4+len(w.Args) {
		t.Fatalf("%s next=%d args=%d", w.SQL, w.NextArg, len(w.Args))
	}
	assertPlaceholders(t, w, 4)
}

func TestFieldPermissionIsUnknownField(t *testing.T) {
	reg := testRegistry(t)
	s := mustParse(t, "pentest_note=x", testOpts())
	_, err := Compile(s, reg, memberActor(t))
	fe, ok := AsError(err)
	if !ok || fe.Details[0].Reason != "unknown field" || fe.Details[0].Param != "pentest_note" {
		t.Fatalf("filter on a forbidden field: %v", err)
	}
	s = mustParse(t, "sort=-pentest_note", testOpts())
	if _, err := Compile(s, reg, memberActor(t)); err == nil {
		t.Fatal("sorting by a forbidden field is an oracle and must fail")
	}
	allowed, _ := UserActor(UserActorInput{TenantID: tenantA, UserID: userA, Has: func(p string) bool { return p == "pentest:read" }})
	if _, err := Compile(mustParse(t, "pentest_note=x&sort=pentest_note", testOpts()), reg, allowed); err != nil {
		t.Fatalf("with the permission: %v", err)
	}
	if _, err := Compile(mustParse(t, "pentest_note=x", testOpts()), reg, SystemActor(tenantA, "t")); err != nil {
		t.Fatalf("system actor: %v", err)
	}
}

func TestCompileOperators(t *testing.T) {
	reg := testRegistry(t)
	cases := map[string]string{
		"severity=high":                       "(f.severity = $2)",
		"severity=high,low":                   "(f.severity = ANY($2::text[]))",
		"status_not=resolved":                 "(f.status <> ALL($2::text[]))",
		"epss_score_lt=0.2":                   "(f.epss_score < $2)",
		"network_port=22,23":                  "(f.port = ANY($2::bigint[]))",
		"asset_id=" + userA.String():          "(f.asset_id = $2::uuid)",
		"assigned_to_null=true":               "(f.assigned_to IS NULL)",
		"assigned_to_null=false":              "(f.assigned_to IS NOT NULL)",
		"file_path_contains=a_b%25":           `(f.file_path ILIKE $2 ESCAPE '\')`,
		"last_seen_at_gte=2026-01-01":         "(f.last_seen_at >= $2::timestamptz)",
		"is_in_kev=false":                     "(f.is_in_kev = $2::boolean)",
		"asset_tag_not=prod":                  "(NOT EXISTS (SELECT 1 FROM assets a WHERE a.id = f.asset_id AND a.tenant_id = f.tenant_id AND a.tags && $2::text[]))",
		"related_to=me":                       "(f.assigned_to = $2::uuid)",
		"epss_score_gte=0.1&epss_score_lte=1": "(f.epss_score <= $3)",
	}
	for raw, want := range cases {
		t.Run(raw, func(t *testing.T) {
			w, err := Compile(mustParse(t, raw, testOpts()), reg, adminActor(t))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(w.SQL, want) {
				t.Fatalf("want %q in %s", want, w.SQL)
			}
			assertPlaceholders(t, w, 1)
		})
	}
	w, _ := Compile(mustParse(t, "file_path_contains=a_b%25", testOpts()), reg, adminActor(t))
	if w.Args[1] != `%a\_b\%%` {
		t.Fatalf("LIKE metacharacters must be escaped: %q", w.Args[1])
	}
}

func TestCompileNullableNotIn(t *testing.T) {
	reg := MustRegistry(Registry{Name: "x", TenantSQL: "t.tenant_id", ScopeAssetSQL: "t.asset_id", IDSQL: "t.id"},
		Field{Name: "owner_id", Type: TypeID, Ops: []Op{OpIn, OpNotIn}, SQL: "t.owner_id", Nullable: true})
	q, _ := url.ParseQuery("owner_id_not=" + userA.String())
	s, err := ParseValues(q, reg, testOpts())
	if err != nil {
		t.Fatal(err)
	}
	w, _ := Compile(s, reg, SystemActor(tenantA, "t"))
	if !strings.Contains(w.SQL, "OR t.owner_id IS NULL") {
		t.Fatalf("not-in on a nullable field must keep NULL rows: %s", w.SQL)
	}
}

func TestOrderBy(t *testing.T) {
	reg := testRegistry(t)
	w, _ := Compile(mustParse(t, "", testOpts()), reg, adminActor(t))
	if w.OrderBy != "f.severity_rank DESC, f.id" {
		t.Fatalf("default sort: %q", w.OrderBy)
	}
	w, _ = Compile(mustParse(t, "sort=last_seen_at,-epss_score", testOpts()), reg, adminActor(t))
	if w.OrderBy != "f.last_seen_at ASC, f.epss_score DESC NULLS LAST, f.id" {
		t.Fatalf("sort: %q", w.OrderBy)
	}
}

func TestWithoutDropsTopLevelField(t *testing.T) {
	s := mustParse(t, "severity=high&status=new", testOpts())
	w := s.Without("severity")
	if len(w.Leaves()) != 1 || w.Leaves()[0].Field != "status" || len(s.Leaves()) != 2 {
		t.Fatalf("Without: %+v / %+v", w.Leaves(), s.Leaves())
	}
}

func TestDocumentSchemaIsValidJSON(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal(DocumentSchema, &v); err != nil {
		t.Fatalf("schema: %v", err)
	}
	if v["title"] != "FilterDocument" {
		t.Fatalf("schema title: %v", v["title"])
	}
}

var placeholderRE = regexp.MustCompile(`\$(\d+)`)

// assertPlaceholders checks that the SQL uses exactly the placeholders
// first..first+len(args)-1: one bound argument per placeholder number.
func assertPlaceholders(t testing.TB, w *Where, first int) {
	t.Helper()
	seen := map[string]bool{}
	for _, m := range placeholderRE.FindAllStringSubmatch(w.SQL, -1) {
		seen[m[1]] = true
	}
	if len(seen) != len(w.Args) {
		t.Fatalf("%d distinct placeholders for %d args: %s", len(seen), len(w.Args), w.SQL)
	}
	for i := range w.Args {
		if !seen[strconv.Itoa(first+i)] {
			t.Fatalf("placeholder $%d missing: %s", first+i, w.SQL)
		}
	}
}

func TestRebase(t *testing.T) {
	reg := MustRegistry(Registry{Name: "x", TenantSQL: "findings.tenant_id", ScopeAssetSQL: "findings.asset_id", IDSQL: "findings.id",
		MemberVisibility: "findings.source <> 'pentest' OR x_findings.y = {user}",
		Search:           &Search{Template: "findings.title ILIKE {arg}"}},
		Field{Name: "tag", Type: TypeString, Ops: []Op{OpIn}, SQL: "findings.tag",
			Templates: map[Op]string{OpIn: "findings.asset_id IN (SELECT a.id FROM assets a WHERE a.tenant_id = findings.tenant_id AND a.tags && {arg})"}})
	rb := reg.Rebase("findings", "f")
	w, err := Compile(&Spec{Root: &Node{All: []*Node{{Leaf: &Leaf{Field: "tag", Op: OpIn, Values: []any{"a"}}}}}, Q: "q"}, rb, memberActor(t))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(w.SQL, "findings.") && !strings.Contains(w.SQL, "x_findings.") {
		t.Fatalf("rebase left a qualifier: %s", w.SQL)
	}
	if !strings.HasPrefix(w.SQL, "f.tenant_id = $1 AND (f.asset_id IN") || !strings.Contains(w.SQL, "x_findings.y") {
		t.Fatalf("rebase: %s", w.SQL)
	}
	if reg.TenantSQL != "findings.tenant_id" {
		t.Fatal("rebase must not change the original")
	}
	if w.First != 1 {
		t.Fatalf("First = %d", w.First)
	}
}

func TestBoolTemplate(t *testing.T) {
	reg := MustRegistry(Registry{Name: "x", TenantSQL: "t.tenant_id", ScopeAssetSQL: "t.asset_id", IDSQL: "t.id"},
		Field{Name: "has_exploit", Type: TypeBool, Ops: []Op{OpEq}, SQL: "t.meta", BoolTemplate: "(t.meta->>'x') = 'true'"})
	for v, want := range map[string]string{
		"true":  "f",
		"false": "(NOT COALESCE((",
	} {
		s, err := ParseValues(url.Values{"has_exploit": {v}}, reg, testOpts())
		if err != nil {
			t.Fatal(err)
		}
		w, err := Compile(s, reg, SystemActor(tenantA, "t"))
		if err != nil {
			t.Fatal(err)
		}
		if v == "true" && !strings.Contains(w.SQL, "(((t.meta->>'x') = 'true'))") || v == "false" && !strings.Contains(w.SQL, want) {
			t.Fatalf("%s: %s", v, w.SQL)
		}
		assertPlaceholders(t, w, 1)
	}
	if _, err := NewRegistry(Registry{Name: "x", TenantSQL: "t.tenant_id", ScopeAssetSQL: "t.asset_id", IDSQL: "t.id"},
		Field{Name: "n", Type: TypeString, Ops: []Op{OpEq}, SQL: "t.n", BoolTemplate: "x"}); err == nil {
		t.Fatal("BoolTemplate on a string field must be rejected")
	}
}

func TestDescribeHidesPermissionFields(t *testing.T) {
	reg := testRegistry(t)
	names := func(d Description) string {
		var n []string
		for _, f := range d.Fields {
			n = append(n, f.Name)
		}
		return strings.Join(n, ",")
	}
	if strings.Contains(names(reg.Describe(nil)), "pentest_note") {
		t.Fatal("a permission-gated field must be hidden without the permission")
	}
	d := reg.Describe(func(p string) bool { return p == "pentest:read" })
	if !strings.Contains(names(d), "pentest_note") || d.Aliases["severities"] != "severity" || d.Limits["leaves"] != MaxLeaves {
		t.Fatalf("describe: %+v", d)
	}
	for _, f := range d.Fields {
		if f.Name == "epss_score" && strings.Join(f.Params, ",") != "epss_score_gte,epss_score_lte,epss_score_gt,epss_score_lt" {
			t.Fatalf("epss params: %v", f.Params)
		}
	}
}

func TestSwagParamsAndRewrite(t *testing.T) {
	reg := testRegistry(t)
	params := map[string]SwagParam{}
	for _, p := range reg.SwagParams() {
		params[p.Name] = p
	}
	for name, p := range params {
		if _, _, err := reg.resolveParam(name); err != nil {
			t.Errorf("documented param %q is not accepted by the parser", name)
		}
		_ = p
	}
	for _, name := range reg.Params() {
		if _, isAlias := reg.Aliases[name]; isAlias || reserved[name] {
			continue
		}
		if _, ok := params[name]; !ok {
			t.Errorf("accepted param %q is not documented", name)
		}
	}
	if p := params["severity"]; !p.Array || len(p.Enum) == 0 || p.Type != "string" {
		t.Fatalf("severity: %+v", p)
	}
	src := "a\n\t// filterspec-params: x GET /x\n\t// stale\n\t// end filterspec-params\nb"
	out, blocks, err := RewriteParamBlocks(src, map[string]*Registry{"x": reg})
	if err != nil || len(blocks) != 1 || strings.Contains(out, "stale") || !strings.Contains(out, "@Param  severity  query  []string") {
		t.Fatalf("rewrite: %v %v %s", err, blocks, out)
	}
	if _, _, err := RewriteParamBlocks("// filterspec-params: x\n", map[string]*Registry{"x": reg}); err == nil {
		t.Fatal("a block without an end marker must fail")
	}
	if _, _, err := RewriteParamBlocks("// filterspec-params: nope\n// end filterspec-params", nil); err == nil {
		t.Fatal("an unknown registry must fail")
	}
}

func TestDocumentRoundTrip(t *testing.T) {
	reg := testRegistry(t)
	for _, doc := range []string{
		`{"v":1,"filter":{"all":[{"field":"severity","op":"in","value":["critical","high"]},{"any":[{"field":"is_in_kev","op":"eq","value":true},{"field":"epss_score","op":"gte","value":0.1}]},{"not":{"field":"asset_tag","op":"in","value":["sandbox"]}},{"field":"last_seen_at","op":"gte","value":"2026-09-01T00:00:00Z"}]},"q":"log4j","sort":["-severity","last_seen_at"]}`,
		`{"filter":{"severity":["low"],"epss_score_gte":0.5}}`,
		`{}`,
	} {
		s1, err := ParseDocument([]byte(doc), reg, testOpts())
		if err != nil {
			t.Fatal(err)
		}
		b, err := s1.DocumentJSON()
		if err != nil {
			t.Fatal(err)
		}
		s2, err := ParseDocument(b, reg, testOpts())
		if err != nil {
			t.Fatalf("re-parse %s: %v", b, err)
		}
		w1, _ := Compile(s1, reg, adminActor(t))
		w2, _ := Compile(s2, reg, adminActor(t))
		leafVals := func(s *Spec) string {
			out := ""
			for _, l := range s.Leaves() {
				out += fmt.Sprint(l.Field, l.Op, l.Values)
			}
			return out
		}
		if w1.SQL != w2.SQL || leafVals(s1) != leafVals(s2) || w1.OrderBy != w2.OrderBy {
			t.Fatalf("round trip changed the spec:\n%s %v\n%s %v", w1.SQL, w1.Args, w2.SQL, w2.Args)
		}
	}
}

func TestOverlay(t *testing.T) {
	reg := testRegistry(t)
	stored, _ := ParseDocument([]byte(`{"filter":{"all":[{"field":"severity","op":"in","value":["critical"]},{"field":"status","op":"in","value":["new"]},{"any":[{"field":"is_in_kev","op":"eq","value":true},{"field":"epss_score","op":"gte","value":0.1}]}]},"q":"x","sort":["-severity"]}`), reg, testOpts())
	req := mustParse(t, "severity=low&rule_id=r1&page=2", testOpts())
	out, err := Overlay(stored, req)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]any{}
	for _, l := range out.Leaves() {
		got[l.Field] = append(got[l.Field], l.Values...)
	}
	if fmt.Sprint(got["severity"]) != "[low]" || fmt.Sprint(got["status"]) != "[new]" || len(got["rule_id"]) != 1 ||
		len(got["is_in_kev"]) != 1 || out.Q != "x" || len(out.Sort) != 1 || out.Page != 2 {
		t.Fatalf("overlay: %v q=%q sort=%v page=%d", got, out.Q, out.Sort, out.Page)
	}
}
