package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/brand"
)

func TestLoadBrandDefaults(t *testing.T) {
	b, err := loadBrand()
	if err != nil {
		t.Fatal(err)
	}
	if b.Public() != brand.Default().Public() {
		t.Fatalf("unset BRAND_* changed the brand: %+v", b.Public())
	}
}

func TestLoadBrandFileThenEnv(t *testing.T) {
	dir := t.TempDir()
	svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><rect width="1" height="1"/></svg>`
	if err := os.WriteFile(filepath.Join(dir, "logo.svg"), []byte(svg), 0o600); err != nil {
		t.Fatal(err)
	}
	yml := "name: Acme Exposure\nshort_name: Acme\ndocs_url: https://help.example.com\npowered_by: false\nlogo_light_file: logo.svg\n"
	path := filepath.Join(dir, "brand.yaml")
	if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BRAND_FILE", path)
	t.Setenv("BRAND_SHORT_NAME", "AX")
	b, err := loadBrand()
	if err != nil {
		t.Fatal(err)
	}
	p := b.Public()
	if p.Name != "Acme Exposure" || p.ShortName != "AX" || p.DocsURL != "https://help.example.com" || p.PoweredBy {
		t.Fatalf("brand = %+v", p)
	}
	if !strings.HasPrefix(p.LogoLightURL, brand.AssetPath+"logo-light?v=") {
		t.Fatalf("logo URL = %q", p.LogoLightURL)
	}
}

func TestLoadBrandRefusesUnsafe(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.svg")
	if err := os.WriteFile(bad, []byte(`<svg xmlns="http://www.w3.org/2000/svg" onload="x()"/>`), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]map[string]string{
		"http url":      {"BRAND_DOCS_URL": "http://docs.example.com"},
		"unsafe svg":    {"BRAND_LOGO_LIGHT_FILE": bad},
		"missing image": {"BRAND_FAVICON_FILE": filepath.Join(dir, "none.png")},
		"powered by":    {"BRAND_POWERED_BY": "maybe"},
		"unknown key":   {"BRAND_FILE": writeFile(t, dir, "x.yaml", "unknown_key: x\n")},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			for k, v := range env {
				t.Setenv(k, v)
			}
			if _, err := loadBrand(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
