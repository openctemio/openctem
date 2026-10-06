package validation

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// commandProducers lists every file that creates a sensor command, with the
// gate its targets pass before the command exists. A new producer fails this
// test until it is routed through a gate (scan.Service.ResolveDispatchTargets,
// or validation.CommandDispatcher for validate commands) and listed here.
var commandProducers = map[string]string{
	"internal/app/validation/dispatcher.go":     "CheckTarget (active-probe gate) in CommandDispatcher.Dispatch",
	"internal/app/validation/retest_command.go": "CheckTarget (active-probe gate) in CommandDispatcher.DispatchToolRetest",
	"internal/app/scan/trigger.go":              "scan trigger: resolveScanTargets (exclusions, attribution) + zone routing",
	"internal/app/scan/zones.go":                "scan trigger: zone batches of already-gated targets",
	"internal/app/pipeline/run.go":              "pipeline.WithTargetGate -> scan.ResolveDispatchTargets (run_targets.go)",
	"internal/app/command/service.go":           "POST /commands: scan.CommandGate (command_gate.go)",
	"internal/app/sensor/content.go":            "refresh_content: no target, sends no traffic at an asset",
	"internal/app/tenablesc/service.go":         "connector_sync: no target; the sensor reads Tenable.sc, sends no traffic at an asset",
	"internal/app/tenablesc/scan.go":            "connector_scan: targets from the scan trigger (resolveScanTargets + ResolveDispatchTargets in scan/connector.go) or the coverage Scheduler.gateBatch",
}

// newCommandCall matches a call of the command domain constructor under any
// import alias.
var newCommandCall = regexp.MustCompile(`\b(\w+)\.NewCommand\(`)

func createsCommands(src []byte) bool {
	return newCommandCall.Match(src)
}

func TestEveryCommandProducerIsGated(t *testing.T) {
	root := filepath.Join("..", "..", "..") // api/
	var found []string
	for _, dir := range []string{"internal", "pkg"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if createsCommands(b) {
				rel, _ := filepath.Rel(root, path)
				found = append(found, filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(found)
	if len(found) == 0 {
		t.Fatal("found no command producer; the scan is broken")
	}
	for _, f := range found {
		if _, ok := commandProducers[f]; !ok {
			t.Errorf("%s creates sensor commands but is not a known gated producer: route its targets through "+
				"scan.Service.ResolveDispatchTargets (or validation.CommandDispatcher) and add it to commandProducers", f)
		}
	}
}

// Validate commands are produced only by CommandDispatcher, which gates them.
func TestValidateCommandsOnlyFromTheDispatcher(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	re := regexp.MustCompile(`CommandTypeValidate\b`)
	allowed := map[string]bool{
		"internal/app/validation/dispatcher.go": true, // the producer
	}
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if allowed[rel] || !re.Match(b) {
			return nil
		}
		// Readers (completion hooks, recovery) only compare the type.
		for _, line := range strings.Split(string(b), "\n") {
			if re.MatchString(line) && strings.Contains(line, "NewCommand(") {
				t.Errorf("%s builds a validate command outside validation.CommandDispatcher", rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
