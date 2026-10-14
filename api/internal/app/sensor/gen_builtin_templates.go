//go:build ignore

// gen_builtin_templates writes config_templates_builtin.go from the shipped
// configs/sensor-templates/*.tmpl files. Run: go generate ./internal/app/sensor/
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

func main() {
	dir := filepath.Join("..", "..", "..", "configs", "sensor-templates")
	var b strings.Builder
	b.WriteString(`package sensor

// Code generated from configs/sensor-templates/*.tmpl; DO NOT EDIT BY HAND.
// The built-in templates are the fallback for a missing template file and
// must stay identical to the shipped files (TestTemplates_ShippedFilesMatchBuiltins).
// Regenerate after editing a .tmpl file:
//
//	go generate ./internal/app/sensor/

//go:generate go run ./gen_builtin_templates.go

var builtinTemplates = map[string]string{
`)
	// Every shipped template: each format of the scanning sensor and of the
	// collector (all required), then the <set>-<format> files of each
	// product's snippet set, sorted, so the output is stable.
	formats := []string{"yaml", "env", "docker", "cli", "compose", "kubernetes", "helm", "policy"}
	for _, f := range formats {
		formats = append(formats, "collector-"+f)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.tmpl"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sort.Strings(files)
	for _, f := range files {
		if name := strings.TrimSuffix(filepath.Base(f), ".tmpl"); !slices.Contains(formats, name) {
			formats = append(formats, name)
		}
	}
	for _, f := range formats {
		c, err := os.ReadFile(filepath.Join(dir, f+".tmpl"))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if strings.Contains(string(c), "`") {
			fmt.Fprintf(os.Stderr, "%s.tmpl contains a backtick; the generator embeds it as a raw string\n", f)
			os.Exit(1)
		}
		fmt.Fprintf(&b, "\t%q: `%s`,\n", f, c)
	}
	b.WriteString("}\n")
	if err := os.WriteFile("config_templates_builtin.go", []byte(b.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
