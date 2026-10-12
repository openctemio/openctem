package asset

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// A property synonym (ip, ips, resolved_ips, nameserver, ...) is never
// stored (RFC-042 §6.3.9): every write path folds it with
// NormalizeProperties, and every reader goes through PropertyStrings /
// IPAddresses, which see the synonyms too. Code that indexes a map with a
// synonym key, or builds a map literal with one, either writes a key the
// schema forbids or keeps a key list of its own that drifts from the
// registry. This guard fails on any such use outside the allow-list below.

// synonymKeyAllowed are the (file, key) uses that are not asset properties,
// or that read the one object a synonym name may still hold.
var synonymKeyAllowed = map[string][]string{
	// The CTIS technical ip_address block (an object, which never folds):
	// ingest builds it, promotes its hostname and validates it.
	"internal/app/ingest/processor_assets.go": {"ip_address"},
	"pkg/validator/properties.go":             {"ip_address"},
	// Not asset properties: sensor metadata, audit metadata and credential
	// details that happen to use the same words.
	"internal/infra/controller/sensor_health.go": {"ip_address"},
	"internal/app/sensor/service.go":             {"ip"},
	"internal/app/ingest/identity_backfill.go":   {"ip"},
	"pkg/domain/credential/import.go":            {"ip_address"},
	// The CTIS technical service and certificate blocks: objects stored
	// under the common keys `service` and `certificate`, not top-level
	// properties, so their field names are the CTIS ones.
	"internal/app/ingest/mappers.go": {"auth_required", "self_signed"},
	// A log redaction key, not an asset property.
	"pkg/logger/logger.go": {"encrypted"},
}

func TestPropertySynonyms_NeverIndexedOrWritten(t *testing.T) {
	root, err := filepath.Abs("../../..") // api/
	if err != nil {
		t.Fatal(err)
	}
	synonyms := map[string]bool{}
	for _, s := range PropertySynonyms() {
		synonyms[s] = true
	}
	fset := token.NewFileSet()
	var bad []string
	used := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if rel == "tests" || rel == "vendor" || strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		allowed := synonymKeyAllowed[filepath.ToSlash(rel)]
		check := func(e ast.Expr) {
			lit, ok := e.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return
			}
			key, err := strconv.Unquote(lit.Value)
			if err != nil || !synonyms[key] {
				return
			}
			if slices.Contains(allowed, key) {
				used[filepath.ToSlash(rel)+" "+key] = true
				return
			}
			bad = append(bad, fset.Position(lit.Pos()).String()+": property synonym "+lit.Value)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.IndexExpr:
				check(x.Index)
			case *ast.CompositeLit:
				if isPropertyMapType(x.Type) {
					for _, el := range x.Elts {
						if kv, ok := el.(*ast.KeyValueExpr); ok {
							check(kv.Key)
						}
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for file, keys := range synonymKeyAllowed {
		for _, k := range keys {
			if !used[file+" "+k] {
				bad = append(bad, "allow-list entry no longer used: "+file+" "+k)
			}
		}
	}
	if len(bad) > 0 {
		t.Fatalf("property synonyms used as keys (fold them with NormalizeProperties, read them with "+
			"PropertyStrings/IPAddresses, or name the canonical key):\n  %s", strings.Join(bad, "\n  "))
	}
}

// isPropertyMapType reports whether a composite literal builds a string-keyed
// map: map[string]..., or a named map such as ctis.Properties.
func isPropertyMapType(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.MapType:
		id, ok := t.Key.(*ast.Ident)
		return ok && id.Name == "string"
	case *ast.SelectorExpr:
		return t.Sel.Name == "Properties"
	case *ast.Ident:
		return t.Name == "Properties"
	}
	return false
}
