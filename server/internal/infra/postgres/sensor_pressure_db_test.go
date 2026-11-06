package postgres

// Host pressure narrows dispatch (research/318): the free-slots SQL and
// Sensor.FreeSlots give the same number for every level, with a held
// command or none, fresh or stale.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestSensorFreeSlots_PressureSQLMatchesGo(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewSensorRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)

	for _, level := range []string{"", "ok", "elevated", "overloaded", "bogus"} {
		for _, held := range []int{0, 1, 3} {
			for _, age := range []string{"1 minute", "10 minutes"} {
				name := fmt.Sprintf("level=%q held=%d age=%s", level, held, age)
				id := seedSensor(ctx, t, db, tenant, "online", nil, "nuclei", 0)
				res := `{"cpu_cores": 4}`
				if level != "" {
					res = fmt.Sprintf(`{"cpu_cores": 4, "pressure": {"level": %q}}`, level)
				}
				if _, err := db.ExecContext(ctx, `UPDATE sensors SET max_concurrent_jobs = 5,
					reported_resources = $2::jsonb,
					reported_capacity = '{"slots_total": 5, "slots_free": 5}'::jsonb,
					load_reported_at = NOW() - $3::interval WHERE id = $1`, id.String(), res, age); err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				for range held {
					if _, err := db.ExecContext(ctx, `INSERT INTO commands (id, tenant_id, sensor_id, type, status, payload, acknowledged_at)
						VALUES ($1, $2, $3, 'scan', 'running', '{}', NOW())`,
						shared.NewID().String(), tenant.String(), id.String()); err != nil {
						t.Fatalf("%s: %v", name, err)
					}
				}
				var sqlFree int
				if err := db.QueryRowContext(ctx, `SELECT `+sensorFreeSlotsSQL("sensors")+` FROM sensors WHERE id = $1`, id.String()).Scan(&sqlFree); err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				sn, err := repo.GetByID(ctx, id)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if goFree := sn.FreeSlots(time.Now()); goFree != sqlFree {
					t.Errorf("%s: Go %d, SQL %d", name, goFree, sqlFree)
				}
				fresh := age == "1 minute"
				want := 5 - held
				switch {
				case fresh && level == "overloaded" && held >= 1:
					want = 0
				case fresh && level == "overloaded":
					want = 1
				case fresh && level == "elevated":
					want = min(want, 1)
				}
				if sqlFree != want {
					t.Errorf("%s: SQL %d, want %d", name, sqlFree, want)
				}
			}
		}
	}
}
