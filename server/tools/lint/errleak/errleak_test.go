package errleak

import (
	"bufio"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var scanDirs = []string{"../../../internal", "../../../pkg"}

const baselineFile = "baseline.txt"

func scanSource(t *testing.T, path, src string) []Finding {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		t.Fatal(err)
	}
	return scanFile(fset, f, path)
}

func rules(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Rule)
	}
	return out
}

func TestRules(t *testing.T) {
	src := `package handler
func (h *H) Bad(w http.ResponseWriter, err error, intg *Integration, req Req) {
	apierror.BadRequest(err.Error()).WriteJSON(w)                                  // echo
	apierror.Conflict("could not save: " + err.Error()).WriteJSON(w)               // echo
	apierror.BadRequest(fmt.Sprintf("refused: %v", err)).WriteJSON(w)              // echo
	apierror.New(424, apierror.Code("X"), err.Error()).WriteJSON(w)                // echo
	apierror.NotFound(fmt.Sprintf("integration %s", intg.ID().String())).WriteJSON(w) // id-message
	apierror.BadRequest(fmt.Sprintf("finding %s is closed", req.FindingID)).WriteJSON(w) // id-message
	_ = fmt.Errorf("%w: integration %s has no credentials", shared.ErrValidation, intg.ID()) // wrap-id
	_ = fmt.Errorf("%w: cannot verify: %v", shared.ErrValidation, err)              // wrap-err
	_ = shared.NewDomainError("X", fmt.Sprintf("asset %s", assetID), nil)           // domain-id
	intg.SetError(fmt.Sprintf("Connection test failed: %v", err))                   // status
	run.Fail("Failed to create command: " + err.Error())                            // status
	writeJSON(w, 400, map[string]any{"code": "X", "message": err.Error()})          // raw-json
	_ = ev.WithMessage(fmt.Sprintf("Credential %s deleted", credentialID))          // audit-id
}
func (h *H) Good(w http.ResponseWriter, err error, name string) {
	apierror.BadRequest("Name is required").WriteJSON(w)
	apierror.FromCode(apierror.CodeIntegrationNoCredentials).WithParams(apierror.Params{"name": name}).WriteJSON(w)
	apierror.Forbidden(publicMessage(err)).WriteJSON(w)
	apierror.BadRequest(fmt.Sprintf("%s is outside the scope", name)).WriteJSON(w)
	_ = fmt.Errorf("load integration %s: %w", id, err)
	_ = fmt.Errorf("%w: name is required", shared.ErrValidation)
	intg.SetError("The connection test failed.")
	_ = ev.WithMessage(fmt.Sprintf("Role '%s' created", name))
	cancel()
}`
	got := rules(scanSource(t, "internal/infra/http/handler/x.go", src))
	want := []string{"echo", "echo", "echo", "echo", "id-message", "id-message", "wrap-id", "wrap-err", "domain-id", "status", "status", "raw-json", "audit-id"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("rules\n got %v\nwant %v", got, want)
	}
}

func TestRawJSONOnlyInHTTPLayer(t *testing.T) {
	src := `package worker
func f(err error) map[string]any { return map[string]any{"error": err.Error()} }`
	if got := scanSource(t, "internal/infra/controller/x.go", src); len(got) != 0 {
		t.Fatalf("raw-json outside the HTTP layer is not a response: %v", got)
	}
}

func loadBaseline(t *testing.T) map[string]int {
	t.Helper()
	f, err := os.Open(baselineFile)
	if err != nil {
		t.Fatalf("open %s: %v", baselineFile, err)
	}
	defer f.Close()
	out := map[string]int{}
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.LastIndexByte(line, ' ')
		count, cerr := strconv.Atoi(line[i+1:])
		if i < 0 || cerr != nil {
			t.Fatalf("%s:%d: want `rule path:Func count`, got %q", baselineFile, n, line)
		}
		out[line[:i]] = count
	}
	return out
}

// TestNoNewErrorLeaks fails when a function gains a leak, and when the
// baseline lists more than is left (lower or delete the line: it only
// shrinks). UPDATE_ERRLEAK_BASELINE=1 rewrites it (for shrinking only;
// review the diff).
func TestNoNewErrorLeaks(t *testing.T) {
	counts := map[string]int{}
	lines := map[string][]int{}
	for _, d := range scanDirs {
		fs, err := Scan(d)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fs {
			counts[f.Key()]++
			lines[f.Key()] = append(lines[f.Key()], f.Line)
		}
	}
	if os.Getenv("UPDATE_ERRLEAK_BASELINE") == "1" {
		writeBaseline(t, counts)
		return
	}
	base := loadBaseline(t)
	var bad, stale []string
	for k, n := range counts {
		if n > base[k] {
			bad = append(bad, fmt.Sprintf("%s (lines %v; baseline %d)", k, lines[k], base[k]))
		}
	}
	for k, n := range base {
		if counts[k] < n {
			stale = append(stale, fmt.Sprintf("%s %d -> %d", k, n, counts[k]))
		}
	}
	sort.Strings(bad)
	sort.Strings(stale)
	if len(bad) > 0 {
		t.Errorf("%d function(s) put server-only text into what a person reads:\n  %s\n\n"+
			"Return a registered code instead: apierror.FromCode(apierror.CodeX).WithParams(apierror.Params{\"name\": n}),\n"+
			"or a fixed sentence; log the error with the request id. Name things, never format an id; never pass\n"+
			"err.Error() or a lower error's text to a message or a stored status (docs/architecture/error-responses.md).",
			len(bad), strings.Join(bad, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("baseline lists leaks that are gone; lower or delete these lines in %s:\n  %s", baselineFile, strings.Join(stale, "\n  "))
	}
}

func writeBaseline(t *testing.T, counts map[string]int) {
	t.Helper()
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# Server-only text that reaches what a person reads, per function: `rule path:Func count`.\n")
	b.WriteString("# Shrink-only: TestNoNewErrorLeaks fails on a new leak and on a count that is higher than what is left.\n")
	b.WriteString("# Rules are described in errleak.go.\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s %d\n", k, counts[k])
	}
	if err := os.WriteFile(baselineFile, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}
