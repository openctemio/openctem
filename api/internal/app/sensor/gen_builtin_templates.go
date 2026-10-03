//go:build ignore

// gen_builtin_templates writes config_templates_builtin.go from the shipped
// configs/sensor-templates/*.tmpl files. Run: go generate ./internal/app/sensor/
package main

import (
	"fmt"
	"os"
	"path/filepath"
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
	for _, f := range []string{"yaml", "env", "docker", "cli", "compose", "kubernetes", "helm", "policy"} {
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
