package scan

// Per-host politeness keys of single-scanner commands (RFC-088 §6,
// docs/rfcs/RFC-090-work-pool.md).

import (
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// reachesNoTargetHost reports whether a run of tool with cfg sends nothing
// to the target hosts: its stages only query recursive DNS resolvers,
// third-party sources or a vendor API (stage.ToolNetwork), and its settings
// do not turn it active (custom resolvers can be the target's own name
// servers, stage.IntensityTier). A tool the catalog does not know reaches
// its targets (fail closed).
func reachesNoTargetHost(tool string, cfg map[string]any) bool {
	tool = strings.TrimSpace(tool)
	if tool == "" {
		return false
	}
	return !stage.ToolNetwork(tool).TouchesTargets() && stage.IntensityTier(tool, nil, cfg) < stage.TierActive
}

// holdNoHostsWhenPassive gives a single-scanner command of a tool that
// reaches no target host an empty key list, as a passive workflow stage's
// chunk has (scanrun chunkHostKeys): it never waits while another task of
// the tenant scans the same names, and never holds them back. Without it
// the repository derived keys from the targets (command.AssignHostKeys),
// so a continuous coverage DNS resolution waited behind every port, HTTP
// and template scan of its names, and was ended as "no sensor picked up
// this run's work" while the sensors were idle.
func holdNoHostsWhenPassive(cmd *command.Command, sc *scan.Scan) {
	if cmd == nil || sc == nil || !reachesNoTargetHost(sc.ScannerName, sc.ScannerConfig) {
		return
	}
	cmd.HostKeys = []string{}
}
