package main

import (
	"fmt"

	"github.com/openctemio/openctem/api/internal/extension"
)

// extensionOnlyEnv are settings of features that only an extension provides
// (docs/development/editions.md). In a build without one, a set value means
// the operator expects a feature this build does not have, so the server
// refuses to start instead of silently running without it (an operator who
// asked for an off-box audit copy must never lose it unnoticed).
var extensionOnlyEnv = []string{"ADMIN_AUDIT_SINK"}

// checkExtensionOnlyEnv returns an error naming the first such setting that
// is set while the build has no extension.
func checkExtensionOnlyEnv(getenv func(string) string, edition string) error {
	if edition != extension.Community {
		return nil
	}
	for _, k := range extensionOnlyEnv {
		if getenv(k) != "" {
			return fmt.Errorf("%s is set, but its feature is not part of this %s build: unset it, or run an image that includes it", k, edition)
		}
	}
	return nil
}
