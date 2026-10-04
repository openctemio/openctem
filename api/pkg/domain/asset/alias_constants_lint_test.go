package asset

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// Alias type names are input-only (RFC-042 §6.3.8): no row is stored under
// them once T3 has run, so feature code that compares against one silently
// does nothing (the "silently inert" class this amendment fixes). Only the
// resolver may name them. This guard fails on any other use of an alias
// constant in non-test code.

// aliasConstants maps each alias constant of value_objects.go to its value.
var aliasConstants = map[string]AssetType{
	"AssetTypeHTTPService":         AssetTypeHTTPService,
	"AssetTypeOpenPort":            AssetTypeOpenPort,
	"AssetTypeDiscoveredURL":       AssetTypeDiscoveredURL,
	"AssetTypeWebsite":             AssetTypeWebsite,
	"AssetTypeWebApplication":      AssetTypeWebApplication,
	"AssetTypeAPI":                 AssetTypeAPI,
	"AssetTypeMobileApp":           AssetTypeMobileApp,
	"AssetTypeCompute":             AssetTypeCompute,
	"AssetTypeServerless":          AssetTypeServerless,
	"AssetTypeKubernetesCluster":   AssetTypeKubernetesCluster,
	"AssetTypeKubernetesNamespace": AssetTypeKubernetesNamespace,
	"AssetTypeContainerRegistry":   AssetTypeContainerRegistry,
	"AssetTypeIAMUser":             AssetTypeIAMUser,
	"AssetTypeIAMRole":             AssetTypeIAMRole,
	"AssetTypeServiceAccount":      AssetTypeServiceAccount,
	"AssetTypeDataStore":           AssetTypeDataStore,
	"AssetTypeS3Bucket":            AssetTypeS3Bucket,
	"AssetTypeVPC":                 AssetTypeVPC,
	"AssetTypeSubnet":              AssetTypeSubnet,
	"AssetTypeFirewall":            AssetTypeFirewall,
	"AssetTypeLoadBalancer":        AssetTypeLoadBalancer,
}

// aliasConstantAllowed are the files that may name an alias: where they are
// declared, the CTIS input mapper and the name normaliser (which keys input
// names before they are resolved).
var aliasConstantAllowed = []string{
	"pkg/domain/asset/value_objects.go",
	"pkg/domain/asset/normalize.go",
	"internal/app/ingest/mappers.go",
}

// The list above must be exactly the registry's aliases, so a new alias
// cannot slip past the guard.
func TestAliasConstants_MatchRegistry(t *testing.T) {
	var want, got []string
	for _, d := range registryTypes {
		if d.AliasOf != nil {
			want = append(want, string(d.Type))
		}
	}
	for _, v := range aliasConstants {
		got = append(got, string(v))
	}
	sort.Strings(want)
	sort.Strings(got)
	if !slices.Equal(want, got) {
		t.Fatalf("alias constants %v != registry aliases %v", got, want)
	}
}

func TestAliasConstants_OnlyInTheResolver(t *testing.T) {
	root, err := filepath.Abs("../../..") // api/
	if err != nil {
		t.Fatal(err)
	}
	const importPath = "github.com/openctemio/openctem/api/pkg/domain/asset"
	fset := token.NewFileSet()
	var offenders []string
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "node_modules", "testdata", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if slices.Contains(aliasConstantAllowed, rel) || strings.HasSuffix(rel, "_generated.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		inAssetPkg := strings.HasPrefix(rel, "pkg/domain/asset/") && !strings.Contains(strings.TrimPrefix(rel, "pkg/domain/asset/"), "/")
		local := map[string]bool{} // names this file imports the asset package as
		for _, imp := range f.Imports {
			if strings.Trim(imp.Path.Value, `"`) != importPath {
				continue
			}
			name := "asset"
			if imp.Name != nil {
				name = imp.Name.Name
			}
			local[name] = true
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && local[id.Name] {
					if _, alias := aliasConstants[x.Sel.Name]; alias {
						offenders = append(offenders, fset.Position(x.Pos()).String()+" "+x.Sel.Name)
					}
				}
				return false
			case *ast.Ident:
				if inAssetPkg {
					if _, alias := aliasConstants[x.Name]; alias {
						offenders = append(offenders, fset.Position(x.Pos()).String()+" "+x.Name)
					}
				}
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
	if len(offenders) > 0 {
		t.Fatalf("alias asset types are input-only (RFC-042 §6.3.8); compare on the stored pair "+
			"(CanonicalPair, ScannableBy, DefaultExposure, WithLegacyNames) instead:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}
