package bootstrapadmin

// `bootstrap-admin sensor-token` gives an install a single-use instance
// enrollment token for its bundled sensor, which then enrolls as a shared
// sensor (api/docs/rfcs/RFC-100-shared-sensors.md §7). The admin-cli image's
// entrypoint is this binary; the compose and Helm installs run it once the
// migrations are applied.
//
//	# Register the value the install generated and gave the sensor as a secret
//	SENSOR_INSTANCE_ENROLLMENT_TOKEN=octe_... \
//	  bootstrap-admin sensor-token -from-env SENSOR_INSTANCE_ENROLLMENT_TOKEN -name bundled-sensor
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

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/app/sensorpairing"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
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
		return 0
	}
	out, err := svc.IssueInstanceToken(ctx, in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sensor-token: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "Shared sensor enrollment token %s, single use, valid until %s. Shown once:\n",
		out.ID, out.ExpiresAt.Format(time.RFC3339))
	fmt.Println(out.Token)
	return 0
}
