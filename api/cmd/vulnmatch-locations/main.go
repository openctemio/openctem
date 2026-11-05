// Command vulnmatch-locations folds the version-match findings stored once
// per service of a host into one finding with one location per service, and
// reverts that fold (internal/tools/vulnmatchlocationscmd).
package main

import "github.com/openctemio/openctem/api/internal/tools/vulnmatchlocationscmd"

func main() { vulnmatchlocationscmd.Main() }
