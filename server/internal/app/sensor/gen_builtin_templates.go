//go:build ignore

// gen_builtin_templates writes config_templates_builtin.go from the shipped
// configs/sensor-products/<set>/<format>.tmpl files. Run: go generate ./internal/app/sensor/
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	dir := filepath.Join("..", "..", "..", "configs", "sensor-products")
	var b strings.Builder
	b.WriteString(`package sensor

// Code generated from configs/sensor-products/<set>/<format>.tmpl; DO NOT EDIT BY HAND.
// The built-in templates are the fallback for a missing template file and
// must stay identical to the shipped files (TestTemplates_ShippedFilesMatchBuiltins).
// Regenerate after editing a .tmpl file:
//
//	go generate ./internal/app/sensor/

//go:generate go run ./gen_builtin_templates.go

var builtinTemplates = map[string]string{
`)
	// Every shipped template, keyed "<set>/<format>": one directory per
	// install snippet set (versions.yaml install), sorted so the output is
	// stable.
	files, err := filepath.Glob(filepath.Join(dir, "*", "*.tmpl"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sort.Strings(files)
	for _, f := range files {
		c, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		key := filepath.Base(filepath.Dir(f)) + "/" + strings.TrimSuffix(filepath.Base(f), ".tmpl")
		if strings.Contains(string(c), "`") {
			fmt.Fprintf(os.Stderr, "%s contains a backtick; the generator embeds it as a raw string\n", f)
			os.Exit(1)
		}
		fmt.Fprintf(&b, "\t%q: `%s`,\n", key, c)
	}
	b.WriteString("}\n")
	if err := os.WriteFile("config_templates_builtin.go", []byte(b.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
