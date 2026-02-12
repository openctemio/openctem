package main

import (
	"fmt"
	"os"

	"github.com/openctemio/api/cmd/openctem-admin/cmd"
)

// Version is set by build flags.
var Version = "dev"

func main() {
	cmd.SetVersion(Version)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
