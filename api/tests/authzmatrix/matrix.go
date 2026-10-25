//go:build authzmatrix

package authzmatrix

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Variants of one route x principal cell.
const (
	varOwn   = "own"   // the principal's own organization's ids (fresh ids for writes)
	varCross = "cross" // the other organization's ids (and slug)
	varOOS   = "oos"   // an asset / finding outside a scoped principal's data scope
)

// Outcomes.
const (
	outOK           = "ok"
	outDeny404      = "ok_404"       // denied with 404 (accepted; weaker than 403)
	outModuleOff    = "module_off"   // MODULE_NOT_ENABLED for the organization
	outInconclusive = "inconclusive" // 429, transport error
	outServerError  = "server_error" // 5xx: recorded, not an authorization verdict
	outWrongAllow   = "allowed"      // passed a gate that should refuse
	outWrongDeny    = "denied"       // refused where the gate admits (broken feature)
	outLeak         = "leak"         // another organization's or out-of-scope data in the body
	outCrossWrite   = "cross_write"  // a write with the other organization's ids answered 2xx
	outUnreachable  = "unreachable"  // 404/405 for every principal: the matrix could not reach the route
	outSkipped      = "skipped"      // self-destructive for the matrix principal (sign-out, leave, delete account)
	outAllowlisted  = "allowlisted"  // reviewed exception (testdata/allowlist.tsv)
	outKnown        = "known_issue"  // confirmed issue tracked under a report id; skipped until fixed
)

type result struct {
	Method    string  `json:"method"`
	Path      string  `json:"path"`
	Feature   string  `json:"feature,omitempty"`
	Class     string  `json:"class,omitempty"`
	Principal string  `json:"principal"`
	Variant   string  `json:"variant"`
	Expected  verdict `json:"expected"`
	Rule      string  `json:"rule"`
	Request   string  `json:"request"`
	Status    int     `json:"status"`
	Code      string  `json:"code,omitempty"`
	Outcome   string  `json:"outcome"`
	Detail    string  `json:"detail,omitempty"`
	Body      string  `json:"body,omitempty"`
	Note      string  `json:"note,omitempty"`
}

func (r result) mismatch() bool {
	switch r.Outcome {
	case outWrongAllow, outWrongDeny, outLeak, outCrossWrite:
		return true
	}
	return false
}

// selfDestructive are writes the matrix never sends as a seeded principal:
// they end its own session or membership, so every later cell would fail.
// The scenario tests cover them with throw-away accounts.
func selfDestructive(r route) bool {
	if r.Method == http.MethodGet {
		return false
	}
	p := r.Path
	switch {
	case strings.HasPrefix(p, "/api/v1/auth/"), strings.HasPrefix(p, "/api/v1/users/me"),
		strings.HasPrefix(p, "/api/v1/me/account"), strings.HasPrefix(p, "/api/v1/organization/leave"),
		strings.Contains(p, "organization-deletion"), strings.Contains(p, "ownership-transfer"),
		r.Method == http.MethodDelete && p == "/api/v1/tenants/{tenant}",
		strings.Contains(p, "/sessions"), strings.Contains(p, "revoke-all"),
		// Organization-wide security switches that would lock the seeded
		// principals out (IP allowlist, MFA and SSO enforcement).
		strings.Contains(p, "ip-allowlist"), strings.Contains(p, "/security"), strings.Contains(p, "sso-enforcement"),
		strings.Contains(p, "identity-policy"):
		return true
	}
	return false
}

// allowEntry is one reviewed exception.
type allowEntry struct {
	method, path, principal, variant, status, reason string
}

func loadAllowlist(t testing.TB) []allowEntry {
	t.Helper()
	f, err := os.Open(filepath.Join(apiRoot(), "tests", "authzmatrix", "testdata", "allowlist.tsv"))
	if err != nil {
		t.Fatalf("allowlist: %v", err)
	}
	defer f.Close()
	var out []allowEntry
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		c := strings.Split(line, "\t")
		if len(c) != 6 || strings.TrimSpace(c[5]) == "" {
			t.Fatalf("allowlist line %d: want 6 tab-separated columns with a reason: %q", n, line)
		}
		if c[4] != "expected" && !strings.HasPrefix(c[4], "known:") {
			t.Fatalf("allowlist line %d: status must be expected or known:<report id>", n)
		}
		out = append(out, allowEntry{c[0], c[1], c[2], c[3], c[4], c[5]})
	}
	return out
}

func globMatch(pattern, s string) bool {
	if pattern == "*" || pattern == s {
		return true
	}
	ok, _ := path.Match(pattern, s)
	return ok
}

func (r *result) applyAllowlist(list []allowEntry) {
	for _, e := range list {
		if globMatch(e.method, r.Method) && globMatch(e.path, r.Path) && globMatch(e.principal, r.Principal) && globMatch(e.variant, r.Variant) {
			r.Note = r.Outcome + ": " + e.reason
			if strings.HasPrefix(e.status, "known:") {
				r.Outcome, r.Note = outKnown, strings.TrimPrefix(e.status, "known:")
			} else {
				r.Outcome = outAllowlisted
			}
			return
		}
	}
}

// matrixRun holds the cells of one pass.
type matrixRun struct {
	w       *world
	allow   []allowEntry
	mu      sync.Mutex
	results []result
	stepped map[*principal]time.Time
}

func (m *matrixRun) add(r result) {
	m.mu.Lock()
	m.results = append(m.results, r)
	m.mu.Unlock()
}

func (m *matrixRun) other(p *principal) *tenant {
	for _, t := range m.w.tenants {
		if p.T != nil && t != p.T {
			return t
		}
	}
	return nil
}

// home is the tenant whose ids an anonymous or tenant-less caller uses.
func (m *matrixRun) home(p *principal) *tenant {
	if p.T != nil {
		return p.T
	}
	return m.w.tenants[0]
}

// freshIDs replaces every parameter but the tenant with a random id, so a
// write that passes its gate finds no row and changes nothing.
func freshIDs(ten *tenant, p string) string {
	return paramRe.ReplaceAllStringFunc(p, func(m string) string {
		if m == "{tenant}" || m == "{org}" {
			return ten.Slug
		}
		return uuid.NewString()
	})
}

// oosPath puts the out-of-scope asset or finding in a route's first asset
// or finding parameter; "" when the route has none.
func oosPath(ten *tenant, p string) string {
	for _, c := range []struct{ coll, key string }{{"/api/v1/assets", "asset.oos"}, {"/api/v1/findings", "finding.oos"}} {
		if !strings.HasPrefix(p, c.coll+"/{") {
			continue
		}
		rest := p[len(c.coll)+1:]
		end := strings.Index(rest, "}")
		out := c.coll + "/" + ten.get(c.key) + rest[end+1:]
		filled, _ := ten.fill(out, true)
		return filled
	}
	return ""
}

func (m *matrixRun) refreshStepUp(t testing.TB, p *principal) {
	if p.Kind != kindUser {
		return
	}
	if time.Since(p.issued) >= tokenMaxAge && !p.issued.IsZero() {
		m.w.freshen(t, p)
		m.mu.Lock()
		m.stepped[p] = time.Now()
		m.mu.Unlock()
		return
	}
	m.mu.Lock()
	last := m.stepped[p]
	m.mu.Unlock()
	if time.Since(last) < 7*time.Minute {
		return
	}
	m.w.stepUp(t, p)
	m.mu.Lock()
	m.stepped[p] = time.Now()
	m.mu.Unlock()
}

// cell sends one request and classifies the answer.
func (m *matrixRun) cell(t testing.TB, r route, p *principal, variant, reqPath string, exp verdict, rule string) {
	var body any
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodDelete {
		body = map[string]any{}
	}
	res := result{Method: r.Method, Path: r.Path, Feature: r.Feature, Class: r.Class, Principal: p.Name, Variant: variant,
		Expected: exp, Rule: rule, Request: r.Method + " " + reqPath}
	resp, err := m.w.c.do(p.cred, r.Method, reqPath, body)
	// API keys have a per-key budget: wait as told and retry.
	for i := 0; i < 8 && err == nil && resp.Status == 429 && p.Kind == kindAPIKey; i++ {
		wait, _ := strconv.Atoi(resp.RetryAfter)
		time.Sleep(time.Duration(min(max(wait, 1), 5)) * time.Second)
		resp, err = m.w.c.do(p.cred, r.Method, reqPath, body)
	}
	if err == nil && resp.Status == 401 && p.Kind == kindUser && strings.Contains(string(resp.Body), "Token has expired") {
		// The matrix outlived the access token: sign in again and retry.
		m.w.resignIn(t, p)
		resp, err = m.w.c.do(p.cred, r.Method, reqPath, body)
	}
	if err == nil && resp.Status == 409 && resp.Code == codePermissionsStale && p.Kind == kindUser {
		// Grants changed since the token was issued (seeding, scenarios):
		// sign in again, as the web client does, and retry once.
		m.w.resignIn(t, p)
		m.mu.Lock()
		m.stepped[p] = time.Now()
		m.mu.Unlock()
		resp, err = m.w.c.do(p.cred, r.Method, reqPath, body)
	}
	if err == nil && resp.Status == 403 && resp.Code == "STEP_UP_REQUIRED" && p.Kind == kindUser {
		m.mu.Lock()
		m.stepped[p] = time.Time{}
		m.mu.Unlock()
		m.refreshStepUp(t, p)
		resp, err = m.w.c.do(p.cred, r.Method, reqPath, body)
	}
	if err != nil {
		res.Outcome, res.Detail = outInconclusive, err.Error()
		m.add(res)
		return
	}
	res.Status, res.Code = resp.Status, resp.Code
	res.Outcome = classify(r, exp, variant, resp)
	if res.Outcome == outCrossWrite || res.Outcome == outWrongAllow || res.Outcome == outWrongDeny {
		res.Body = excerpt(resp.Body)
	}
	// Body checks: another organization's ids never appear; a scoped
	// principal never sees out-of-scope rows on a scoped route.
	if resp.Status < 300 || resp.Status >= 400 {
		if leak := m.leakIn(p, r, reqPath, resp.Body); leak != "" && res.Outcome != outInconclusive {
			res.Outcome, res.Detail, res.Body = outLeak, leak, excerpt(resp.Body)
		}
	}
	if res.mismatch() {
		res.applyAllowlist(m.allow)
	}
	m.add(res)
}

func classify(r route, exp verdict, variant string, resp response) string {
	s := resp.Status
	switch {
	case s == 429:
		return outInconclusive
	case s >= 500:
		return outServerError
	case s == 403 && resp.Code == "MODULE_NOT_ENABLED":
		return outModuleOff
	case s == 409 && resp.Code == codePermissionsStale:
		// A token issued before a grant change: the caller must refresh.
		return outInconclusive
	}
	denied := s == 401 || s == 403
	if variant == varCross && r.Method != http.MethodGet && s >= 200 && s < 300 && strings.Contains(r.Path, "{") {
		return outCrossWrite
	}
	switch exp {
	case vAllow:
		if denied {
			return outWrongDeny
		}
		if variant == varOOS && r.Class == "scoped" && s >= 200 && s < 300 {
			return outLeak
		}
	case vDeny:
		if denied {
			return outOK
		}
		if s == 404 {
			return outDeny404
		}
		if s == 405 {
			return outOK
		}
		return outWrongAllow
	}
	return outOK
}

func excerpt(b []byte) string {
	b = bytes.TrimSpace(b)
	if len(b) > 240 {
		b = append(b[:240:240], []byte("...")...)
	}
	return string(b)
}

// leakIn returns the first foreign marker in a response body.
func (m *matrixRun) leakIn(p *principal, r route, reqPath string, body []byte) string {
	if len(body) == 0 {
		return ""
	}
	s := string(body)
	if o := m.other(p); o != nil {
		for _, mk := range o.markerList() {
			// An id the request itself named and the answer echoes (a
			// "not found" message) is not a leak.
			if strings.Contains(s, mk) && !strings.Contains(reqPath, mk) {
				return "other organization marker " + mk
			}
		}
	}
	if p.scoped && p.T != nil && r.Class == "scoped" {
		for _, k := range []string{"asset.oos", "finding.oos", "asset.oos.ingest", "asset.victim", "finding.victim"} {
			if id := p.T.get(k); id != "" && strings.Contains(s, id) && !strings.Contains(reqPath, id) {
				return "out-of-scope " + k
			}
		}
	}
	return ""
}

// run sends every route as every principal (writes only when writes is set).
func (m *matrixRun) run(t *testing.T, routes []route, principals []*principal, writes bool) {
	jobs := make(chan *principal)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				m.runPrincipal(t, routes, p, writes)
			}
		}()
	}
	for _, p := range principals {
		jobs <- p
	}
	close(jobs)
	wg.Wait()
}

func (m *matrixRun) runPrincipal(t *testing.T, routes []route, p *principal, writes bool) {
	home, other := m.home(p), m.other(p)
	for _, r := range routes {
		isWrite := r.Method != http.MethodGet && r.Method != http.MethodHead
		if isWrite != writes {
			continue
		}
		exp, rule := expected(r, p)
		if isWrite && selfDestructive(r) {
			if p.Kind == kindUser || p.Kind == kindAPIKey {
				m.add(result{Method: r.Method, Path: r.Path, Feature: r.Feature, Class: r.Class, Principal: p.Name, Variant: varOwn,
					Expected: exp, Rule: rule, Outcome: outSkipped})
				continue
			}
		}
		m.refreshStepUp(t, p)
		own, _ := home.fill(r.Path, true)
		if isWrite {
			own = freshIDs(home, r.Path)
		}
		m.cell(t, r, p, varOwn, own, exp, rule)
		if other != nil {
			// Only when some parameter takes a real value of the other
			// organization (a random id says nothing about isolation).
			if cross, real := other.fillCross(r.Path); real {
				m.cell(t, r, p, varCross, cross, crossVerdict(exp), rule+" (other organization's ids)")
			}
		}
		if p.scoped && !isWrite && exp == vAllow {
			if q := oosPath(home, r.Path); q != "" {
				m.cell(t, r, p, varOOS, q, exp, rule+" (out-of-scope id)")
			}
		}
	}
}

// crossVerdict: with the other organization's ids a request passes its
// gate (the gate is about the caller) but must find nothing; the matrix
// checks this through the body and cross-write rules, not the status.
func crossVerdict(v verdict) verdict {
	if v == vAllow {
		return vAny
	}
	return v
}

// markUnreachable flags routes no principal could reach (404/405 for
// everyone), so a wrong path never passes as "denied".
func markUnreachable(results []result) {
	reach := map[string]bool{}
	for _, r := range results {
		if r.Variant == varOwn && r.Status != 0 && r.Status != 404 && r.Status != 405 && r.Status != 401 {
			reach[r.Method+" "+r.Path] = true
		}
	}
	for i := range results {
		r := &results[i]
		if r.Status != 0 && !reach[r.Method+" "+r.Path] && r.Outcome == outDeny404 {
			r.Outcome = outUnreachable
		}
	}
}

type summary struct {
	Routes, Principals, Cells int
	ByOutcome                 map[string]int
}

func summarize(results []result) summary {
	s := summary{ByOutcome: map[string]int{}}
	routes, principals := map[string]bool{}, map[string]bool{}
	for _, r := range results {
		routes[r.Method+" "+r.Path] = true
		principals[r.Principal] = true
		s.ByOutcome[r.Outcome]++
	}
	s.Routes, s.Principals, s.Cells = len(routes), len(principals), len(results)
	return s
}

func writeReport(t testing.TB, name string, results []result) {
	dst := os.Getenv("MATRIX_REPORT")
	if dst == "" {
		return
	}
	sort.Slice(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Method != b.Method {
			return a.Method < b.Method
		}
		if a.Principal != b.Principal {
			return a.Principal < b.Principal
		}
		return a.Variant < b.Variant
	})
	raw, _ := json.MarshalIndent(map[string]any{"summary": summarize(results), "results": results}, "", " ")
	file := strings.TrimSuffix(dst, ".json") + "-" + name + ".json"
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		t.Logf("report: %v", err)
	}
}

func failOnMismatches(t *testing.T, results []result) {
	n := 0
	for _, r := range results {
		if !r.mismatch() {
			continue
		}
		n++
		if n <= 200 {
			t.Errorf("%s %s as %s (%s): expected %s [%s], got %d %s %s %s", r.Method, r.Path, r.Principal, r.Variant,
				r.Expected, r.Rule, r.Status, r.Code, r.Outcome, r.Detail)
		}
	}
	s := summarize(results)
	t.Logf("matrix: %d routes x %d principals, %d cells, outcomes %v", s.Routes, s.Principals, s.Cells, s.ByOutcome)
	if n > 200 {
		t.Errorf("... %d mismatches in all", n)
	}
	_ = fmt.Sprint
}
