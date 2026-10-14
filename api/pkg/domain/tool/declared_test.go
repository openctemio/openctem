package tool

import (
	"errors"
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
