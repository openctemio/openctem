// Command envdoc writes the files generated from the environment variable
// registry (internal/config/env_registry.yaml): server/.env.example and
// server/docs/configuration/environment-variables.md. Run from server/:
//
//	go run ./cmd/envdoc          (make env-docs)
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/openctemio/openctem/server/internal/config"
)

func main() {
	r := config.Registry()
	files := map[string]string{
		config.EnvExamplePath:   config.RenderEnvExample(r),
		config.EnvReferencePath: config.RenderEnvReference(r),
	}
	for path, body := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("wrote", path)
	}
}
