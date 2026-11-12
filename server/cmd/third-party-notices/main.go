// Command third-party-notices writes the API's third-party notices: every
// module linked into the server binary, with its version, license and license
// text, read from the module cache (no network). The API image runs it at
// build time and serves the file at GET /api/v1/licenses and
// /api/v1/admin/licenses (About > Open-source licenses). Run from server/:
//
//	go run ./cmd/third-party-notices -o third-party-notices.json
//
// Design: docs/architecture/third-party-notices.md.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/openctemio/openctem/server/pkg/notices"
)

func main() {
	out := flag.String("o", notices.DefaultPath, "output file")
	pkg := flag.String("pkg", "./cmd/server", "the main package whose dependencies are listed")
	flag.Parse()
	if err := run(*out, *pkg); err != nil {
		fmt.Fprintln(os.Stderr, "third-party-notices:", err)
		os.Exit(1)
	}
}

func run(out, pkg string) error {
	ctx := context.Background()
	if strings.HasPrefix(pkg, "-") {
		return fmt.Errorf("invalid package %q", pkg)
	}
	var list bytes.Buffer
	cmd := exec.CommandContext(ctx, "go", "list", "-deps", "-json", pkg) // #nosec G204 -- build-time tool, package from its own flag
	cmd.Stdout = &list
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go list: %w", err)
	}
	mods, err := notices.ParseGoList(&list)
	if err != nil {
		return err
	}
	pkgs, err := notices.GoPackages(mods)
	if err != nil {
		return err
	}
	goroot, err := goEnv(ctx, "GOROOT")
	if err != nil {
		return err
	}
	goVersion, err := goEnv(ctx, "GOVERSION")
	if err != nil {
		return err
	}
	std, err := notices.GoStdlib(goroot, goVersion)
	if err != nil {
		return err
	}
	pkgs = append(pkgs, std)
	notices.Sort(pkgs)

	data, err := json.MarshalIndent(notices.Document{Generated: true, Component: "api", Packages: pkgs}, "", " ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, append(data, '\n'), 0o644); err != nil { // #nosec G306 -- public notices, read by the API user
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d packages)\n", out, len(pkgs))
	return nil
}

func goEnv(ctx context.Context, name string) (string, error) {
	b, err := exec.CommandContext(ctx, "go", "env", name).Output() // #nosec G204 -- fixed variable names
	if err != nil {
		return "", fmt.Errorf("go env %s: %w", name, err)
	}
	return strings.TrimSpace(string(b)), nil
}
