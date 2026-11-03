//go:build ee

package main

// The build switch: the only file that imports the extension overlay mounted
// at api/ee, and the only file that may carry this build tag (the edition
// fence enforces both). The overlay registers itself with pkg/extension
// from an init function. See docs/development/editions.md.
import _ "github.com/openctemio/openctem/api/ee"
