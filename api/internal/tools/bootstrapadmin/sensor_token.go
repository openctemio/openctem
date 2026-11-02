package bootstrapadmin

// `bootstrap-admin sensor-token` gives an install a single-use instance
// enrollment token for its bundled sensor, which then enrolls as a shared
// sensor (api/docs/rfcs/RFC-100-shared-sensors.md §7). The API image ships it as
// /app/bootstrap-admin; the compose and Helm installs run it once the
// migrations are applied.
//
//	# Register the value the install generated and gave the sensor as a secret
//	SENSOR_INSTANCE_ENROLLMENT_TOKEN=octe_... \
//	  bootstrap-admin sensor-token -from-env SENSOR_INSTANCE_ENROLLMENT_TOKEN -name bundled-sensor
//	# A new install whose bundled sensor relays the feeds (zero egress):
//	# relay mode, the sensor designated once it enrolls with this token
//	  bootstrap-admin sensor-token -from-env SENSOR_INSTANCE_ENROLLMENT_TOKEN -feed-relay
//	# Or mint one and print it once (an operator enrolling a sensor by hand)
//	  bootstrap-admin sensor-token -name central-01 -reason "central scanner"
//
// It needs DATABASE_URL (or DB_*) and the API's APP_ENCRYPTION_KEY (and
// SENSOR_KEY_PEPPER when the API sets one): the token is stored as the keyed
// hash the API checks. The token lives at most an hour and is spent by the
// first sensor that presents it; a value already registered is reported and
// left alone, so an install can run the step again. Each new token writes a
// console audit row (actor "bootstrap").

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/openctemio/openctem/api/internal/app/feedrelay"
	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/app/sensorpairing"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func runSensorToken(args []string) int {
	fs := flag.NewFlagSet("sensor-token", flag.ContinueOnError)
	dbURL := fs.String("db", "", "Database URL (or set DATABASE_URL env)")
	fromEnv := fs.String("from-env", "", "Register the token in this environment variable instead of minting one")
	name := fs.String("name", "", "Name the shared sensor gets (default: its host name)")
	reason := fs.String("reason", "bundled sensor of the install", "Why the token is issued (audited)")
	ttl := fs.Duration("ttl", time.Hour, "Lifetime, 5m to 1h")
	feedRelay := fs.Bool("feed-relay", false, "New install only: receive every feed through this sensor (relay mode, docs/rfcs/RFC-142-feed-relay.md); ignored once the feed delivery setting exists")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	key := os.Getenv("APP_ENCRYPTION_KEY")
	if key == "" {
		fmt.Fprintln(os.Stderr, "sensor-token: APP_ENCRYPTION_KEY (the API's) is required")
		return 2
	}
	databaseURL := firstNonEmpty(*dbURL, os.Getenv("DATABASE_URL"), databaseURLFromParts())
	if databaseURL == "" {
		fmt.Fprintln(os.Stderr, "sensor-token: database URL required (-db, DATABASE_URL or DB_* env vars)")
		return 2
	}
	var token string
	if *fromEnv != "" {
		if token = os.Getenv(*fromEnv); token == "" {
			fmt.Fprintf(os.Stderr, "sensor-token: %s is empty\n", *fromEnv)
			return 2
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sensor-token: %v\n", err)
		return 1
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "sensor-token: database: %v\n", err)
		return 1
	}
	pepper, _ := sensorapp.SensorKeyPeppers(os.Getenv("SENSOR_KEY_PEPPER"), key)
	log := logger.New(logger.Config{Level: "warn", Format: "text", Output: os.Stderr})
	pdb := &postgres.DB{DB: db}
	svc, err := sensorpairing.NewService(postgres.NewSensorPairingRepository(pdb), postgres.NewSensorRepository(pdb), key, pepper, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sensor-token: %v\n", err)
		return 1
	}
	svc.SetAdminAudit(postgres.NewAuditLogRepository(pdb))
	in := sensorpairing.IssueInstanceTokenInput{Name: *name, Reason: *reason, TTL: *ttl}

	if token != "" {
		out, err := svc.RegisterInstanceToken(ctx, token, in)
		switch {
		case errors.Is(err, shared.ErrConflict):
			fmt.Fprintf(os.Stderr, "sensor-token: the value in %s is already registered; nothing changed\n", *fromEnv)
			return 0
		case err != nil:
			fmt.Fprintf(os.Stderr, "sensor-token: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "Registered shared sensor enrollment token %s (from %s), valid until %s.\n",
			out.ID, *fromEnv, out.ExpiresAt.Format(time.RFC3339))
		if *feedRelay {
			return seedFeedRelay(ctx, pdb, out.ID)
		}
		return 0
	}
	out, err := svc.IssueInstanceToken(ctx, in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sensor-token: %v\n", err)
		return 1
	}
	if *feedRelay {
		if rc := seedFeedRelay(ctx, pdb, out.ID); rc != 0 {
			return rc
		}
	}
	fmt.Fprintf(os.Stderr, "Shared sensor enrollment token %s, single use, valid until %s. Shown once:\n",
		out.ID, out.ExpiresAt.Format(time.RFC3339))
	fmt.Println(out.Token)
	return 0
}

// seedFeedRelay stores relay mode for a new install, with the token whose
// sensor the platform designates as the relay once it enrolls and reports
// feed.relay@1. An installation that already has the setting (every
// existing one: the feed relay migration records direct mode) is left alone,
// and writes a console audit row when it changes something.
func seedFeedRelay(ctx context.Context, pdb *postgres.DB, tokenID shared.ID) int {
	written, err := feedrelay.SeedRelayMode(ctx, postgres.NewPlatformSettingRepository(pdb), tokenID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sensor-token: feed delivery: %v\n", err)
		return 1
	}
	if !written {
		fmt.Fprintln(os.Stderr, "Feed delivery is already set on this installation; unchanged.")
		return 0
	}
	entry := admin.NewAuditLogBuilder(nil, feedrelay.ActionChanged).Resource("platform_setting", nil, feedrelay.ModeKey).
		Request("", "", map[string]any{"mode": feedrelay.ModeRelay, "bootstrap_token_id": tokenID.String()}).Response(200).High().Build()
	entry.AdminEmail = "bootstrap"
	if err := postgres.NewAuditLogRepository(pdb).Create(ctx, entry); err != nil {
		fmt.Fprintf(os.Stderr, "sensor-token: feed delivery audit: %v\n", err)
	}
	fmt.Fprintln(os.Stderr, "Feed delivery: relay mode; the bundled sensor relays every feed once it enrolls.")
	return 0
}
