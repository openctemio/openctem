// Command gen-authz-docs generates the authorization reference from the
// source: the permission catalog, the built-in roles, the role templates, the
// route gates (permission, team role, module, step-up), the data-scope
// classification of every route, the personas and the recommended teams.
//
// Usage (from api/):
//
//	go run ./cmd/gen-authz-docs                         # write the web JSON
//	go run ./cmd/gen-authz-docs -md ../docs-out         # also write markdown pages
//	go run ./cmd/gen-authz-docs -md DIR -front-matter   # with documentation site front matter
//
// The JSON (web/src/config/authz-matrix.json) is generated, not committed,
// like the other contract files: `make generate` at the repository root
// writes it. The documentation site regenerates its pages from a release.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/openctemio/openctem/api/internal/authzdoc"
)

func main() {
	jsonPath := flag.String("json", "../web/src/config/authz-matrix.json", "where to write the JSON for the web console (empty: skip)")
	mdDir := flag.String("md", "", "directory to write the markdown pages into (empty: skip)")
	fm := flag.Bool("front-matter", false, "add the documentation site's front matter to the markdown pages")
	flag.Parse()

	if _, err := os.Stat("go.mod"); err != nil {
		fmt.Fprintln(os.Stderr, "gen-authz-docs: run from api/")
		os.Exit(2)
	}
	ref, err := authzdoc.Build(".")
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen-authz-docs:", err)
		os.Exit(1)
	}
	if *jsonPath != "" {
		b, err := ref.JSON()
		if err == nil {
			err = writeFile(*jsonPath, b)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "gen-authz-docs:", err)
			os.Exit(1)
		}
	}
	if *mdDir != "" {
		for _, p := range ref.Markdown(authzdoc.MarkdownOptions{FrontMatter: *fm}) {
			if err := writeFile(filepath.Join(*mdDir, p.Path), p.Content); err != nil {
				fmt.Fprintln(os.Stderr, "gen-authz-docs:", err)
				os.Exit(1)
			}
		}
	}
}

func writeFile(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
