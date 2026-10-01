package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"

	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/logger"
)

// runSensorUpgradeCheck prints every probe of the agent → sensor upgrade check
// (RFC-023 §9.5) and returns the process exit code: 0 when nothing the
// migration should have converted is left, 1 otherwise.
//
//	docker compose exec api ./server -sensor-upgrade-check
func runSensorUpgradeCheck(ctx context.Context, db *sql.DB, w io.Writer) int {
	items, err := postgres.CheckSensorRename(ctx, db, true)
	if err != nil {
		_, _ = fmt.Fprintf(w, "sensor upgrade check failed: %v\n", err)
		return 1
	}
	leftovers := 0
	for _, it := range items {
		status := "ok"
		switch {
		case it.Kept && it.Count > 0:
			status = "kept"
		case it.Leftover():
			status = "LEFTOVER"
			leftovers++
		}
		_, _ = fmt.Fprintf(w, "%-8s %-6s %8d  %s\n", status, it.Area, it.Count, it.What)
		if it.Kept && it.Count > 0 {
			_, _ = fmt.Fprintf(w, "%26s(%s)\n", "", it.Reason)
		}
	}
	if leftovers > 0 {
		_, _ = fmt.Fprintf(w, "\n%d check(s) found pre-sensor vocabulary the upgrade should have converted. "+
			"Run migrations up to 000230 (migrate ... up) and re-run this check.\n", leftovers)
		return 1
	}
	_, _ = fmt.Fprintln(w, "\nUpgrade complete: no pre-sensor vocabulary left outside the kept history.")
	return 0
}

// logSensorUpgradeLeftovers runs the cheap probes at startup and warns when
// the agent → sensor data migration left something behind. Never fatal.
func logSensorUpgradeLeftovers(ctx context.Context, db *sql.DB, log *logger.Logger) {
	items, err := postgres.CheckSensorRename(ctx, db, false)
	if err != nil {
		log.Warn("sensor upgrade check could not run", "error", err)
		return
	}
	for _, it := range items {
		if it.Leftover() {
			log.Warn("pre-sensor vocabulary left after upgrade; run `server -sensor-upgrade-check` for details",
				"area", it.Area, "check", it.What, "count", it.Count)
		}
	}
}
