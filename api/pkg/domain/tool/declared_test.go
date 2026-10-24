package tool

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func toyDeclaration() Declaration {
	return Declaration{
		Name: "toyweb", Version: "0.1.0", DisplayName: "Toy web checker",
		Description: "Checks web origins.", Category: "web", Icon: "shield",
		Implements:   []string{"dast.web@1", "dast.web@1", "vuln.templates@1"},
		Consumes:     []string{"http_service", "website"},
		ConfigSchema: map[string]any{"type": "object"},
		Digest:       "sha256:aa",
	}
}

func TestNewDeclaredTool(t *testing.T) {
	tenant := shared.NewID()
	tl, err := NewDeclaredTool(tenant, toyDeclaration())
	if err != nil {
		t.Fatal(err)
	}
	if tl.TenantID == nil || *tl.TenantID != tenant || tl.IsBuiltin || !tl.IsActive || !tl.IsDeclared() {
		t.Fatalf("row %+v", tl)
	}
	if got := strings.Join(tl.Capabilities, ","); got != "dast.web,vuln.templates" {
		t.Fatalf("capability keys %q", got)
	}
	if tl.DeclaredDigest() != "sha256:aa" || tl.CurrentVersion != "0.1.0" || tl.DisplayName != "Toy web checker" {
		t.Fatalf("row %+v", tl)
	}
	if tl.InstallMethod != "" {
		t.Fatalf("a declared tool has no install method, got %q", tl.InstallMethod)
	}
	if _, err := NewDeclaredTool(shared.ID{}, toyDeclaration()); err == nil {
		t.Fatal("a declared tool without an organization is refused")
	}
	d := toyDeclaration()
	d.Name = strings.Repeat("a", 51)
	if _, err := NewDeclaredTool(tenant, d); err == nil {
		t.Fatal("an over-long name is refused")
	}
}

// Reported text is data: bounded, without control or format characters,
// single-line names; nothing is interpreted.
func TestDeclaredToolTextIsSanitized(t *testing.T) {
	d := toyDeclaration()
	d.DisplayName = "  Evil\u202e\x00 <script>alert(1)</script>\n tool " + strings.Repeat("x", 300)
	d.Description = "line one\nline two\x07\u200b " + strings.Repeat("y", 2000)
	d.Category = "WEB<b>"
	d.Icon = strings.Repeat("i", 40)
	tl, err := NewDeclaredTool(shared.NewID(), d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(tl.DisplayName, "\u202e\x00\n") || len([]rune(tl.DisplayName)) > 100 {
		t.Fatalf("display name %q", tl.DisplayName)
	}
	if !strings.Contains(tl.DisplayName, "<script>") {
		t.Fatal("markup is kept as text (rendered escaped), not stripped into something else")
	}
	if !strings.Contains(tl.Description, "line one\nline two") || strings.ContainsAny(tl.Description, "\x07\u200b") ||
		len([]rune(tl.Description)) > 1000 {
		t.Fatalf("description %q", tl.Description)
	}
	if tl.Metadata[MetaCategory] != "" || tl.Metadata[MetaIcon] != "" {
		t.Fatalf("hints must be short machine words: %v", tl.Metadata)
	}
	d.DisplayName = "   "
	tl, _ = NewDeclaredTool(shared.NewID(), d)
	if tl.DisplayName != "toyweb" {
		t.Fatalf("empty display name falls back to the name, got %q", tl.DisplayName)
	}
}

func TestRefreshDeclaration(t *testing.T) {
	newer := func(a, b string) bool { return a > b }
	tl, _ := NewDeclaredTool(shared.NewID(), toyDeclaration())
	tl.IsActive = false // the organization switched it off

	same := toyDeclaration()
	if tl.RefreshDeclaration(same, newer) {
		t.Fatal("the same digest changes nothing")
	}
	older := toyDeclaration()
	older.Version, older.Digest, older.DisplayName = "0.0.9", "sha256:old", "Old"
	if tl.RefreshDeclaration(older, newer) || tl.DisplayName != "Toy web checker" {
		t.Fatal("an older version does not overwrite a newer one")
	}
	next := toyDeclaration()
	next.Version, next.Digest, next.DisplayName = "0.2.0", "sha256:bb", "Toy web checker 2"
	if !tl.RefreshDeclaration(next, newer) || tl.DisplayName != "Toy web checker 2" || tl.DeclaredDigest() != "sha256:bb" {
		t.Fatalf("a newer version refreshes: %+v", tl)
	}
	if tl.IsActive {
		t.Fatal("a refresh never re-activates a tool the organization switched off")
	}

	own, _ := NewTenantCustomTool(shared.NewID(), shared.NewID(), "toyweb", "Mine", nil, InstallBinary)
	if own.RefreshDeclaration(next, newer) || own.DisplayName != "Mine" {
		t.Fatal("a member's own tool is never overwritten by a declaration")
	}
}

func TestCanEditRefusesDeclaredTools(t *testing.T) {
	tenant := shared.NewID()
	tl, _ := NewDeclaredTool(tenant, toyDeclaration())
	if err := tl.CanEdit(tenant); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("editing a declared tool: %v", err)
	}
	if err := tl.CanManage(tenant); err != nil {
		t.Fatalf("activating/deactivating stays the organization's switch: %v", err)
	}
	if err := tl.CanEdit(shared.NewID()); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("another organization: %v", err)
	}
	own, _ := NewTenantCustomTool(tenant, shared.NewID(), "mine", "Mine", nil, InstallBinary)
	if err := own.CanEdit(tenant); err != nil {
		t.Fatalf("own tool: %v", err)
	}
}

// The param mappings are kept per implemented reference only, as machine
// words, bounded; DeclaredImplements reads them back fresh and after a
// round trip through the metadata column (JSON).
func TestDeclaredParams(t *testing.T) {
	d := toyDeclaration()
	d.Params = map[string]map[string]string{
		"vuln.templates@1": {"rate": "rps", "severity": "severity", "Bad.Key": "x", "tags": "a.b"},
		"scan.ports@1":     {"rate": "rate"}, // not implemented: dropped
	}
	tl, err := NewDeclaredTool(shared.NewID(), d)
	if err != nil {
		t.Fatal(err)
	}
	check := func(tl *Tool) {
		t.Helper()
		got, ok := tl.DeclaredImplements("vuln.templates@1")
		if !ok || len(got) != 2 || got["rate"] != "rps" || got["severity"] != "severity" {
			t.Fatalf("vuln.templates@1 params = %v, %v", got, ok)
		}
		if got, ok := tl.DeclaredImplements("dast.web@1"); !ok || len(got) != 0 {
			t.Fatalf("dast.web@1 params = %v, %v (implemented, takes no param)", got, ok)
		}
		if _, ok := tl.DeclaredImplements("scan.ports@1"); ok {
			t.Fatal("a capability the descriptor does not implement was reported")
		}
		if _, ok := tl.DeclaredImplements(""); ok {
			t.Fatal("empty reference reported")
		}
	}
	check(tl)

	raw, err := json.Marshal(tl.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	stored := *tl
	stored.Metadata = meta
	check(&stored)

	// A tool a member created is never read as declared.
	member := &Tool{Name: "mine", Metadata: map[string]any{MetaImplements: []string{"vuln.templates@1"}}}
	if _, ok := member.DeclaredImplements("vuln.templates@1"); ok {
		t.Fatal("a member's tool was read as a declared implementation")
	}

	many := map[string]string{}
	for i := 0; i < 2*maxDeclaredParams; i++ {
		many[fmt.Sprintf("p%d", i)] = "k"
	}
	if got := declaredParams([]string{"vuln.templates@1"}, map[string]map[string]string{"vuln.templates@1": many}); len(got["vuln.templates@1"]) != maxDeclaredParams {
		t.Fatalf("kept %d params, want the bound %d", len(got["vuln.templates@1"]), maxDeclaredParams)
	}
}

// A row projected before the param mappings were kept is refreshed once
// from the same descriptor; after that the same digest changes nothing.
func TestRefreshDeclarationAddsParamsOnce(t *testing.T) {
	d := toyDeclaration()
	tl, err := NewDeclaredTool(shared.NewID(), d)
	if err != nil {
		t.Fatal(err)
	}
	delete(tl.Metadata, MetaParams) // as projected by an older platform
	d.Params = map[string]map[string]string{"vuln.templates@1": {"rate": "rps"}}
	if !tl.RefreshDeclaration(d, func(a, b string) bool { return false }) {
		t.Fatal("a row without param mappings was not refreshed")
	}
	if got, _ := tl.DeclaredImplements("vuln.templates@1"); got["rate"] != "rps" {
		t.Fatalf("params = %v", got)
	}
	if tl.RefreshDeclaration(d, func(a, b string) bool { return false }) {
		t.Fatal("the same digest refreshed the row again")
	}
}
