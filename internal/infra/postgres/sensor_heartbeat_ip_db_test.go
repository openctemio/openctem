package postgres

import (
	"context"
	"net"
	"testing"

	"github.com/openctemio/api/pkg/domain/sensor"
)

// TestUpdateHeartbeat_StoresClientIP: the heartbeat writes the caller's address
// into sensors.ip_address, and a heartbeat with no known address keeps the
// stored one. Before, the column was never written by a heartbeat, so the
// sensor.connected audit message read "connected from ".
func TestUpdateHeartbeat_StoresClientIP(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := &SensorRepository{db: &DB{DB: db}}

	tenantID := seedTestTenant(ctx, t, db)
	id := seedSensor(ctx, t, db, tenantID, "offline", nil, "nuclei", 0)

	ipOf := func() string {
		var ip *string
		if err := db.QueryRowContext(ctx, `SELECT host(ip_address) FROM sensors WHERE id = $1`, id.String()).Scan(&ip); err != nil {
			t.Fatalf("read ip: %v", err)
		}
		if ip == nil {
			return ""
		}
		return *ip
	}

	for _, want := range []string{"203.0.113.9", "2606:4700:4700::1111"} {
		ok, err := repo.UpdateHeartbeat(ctx, id, sensor.HeartbeatUpdate{TenantID: &tenantID, IPAddress: net.ParseIP(want)})
		if err != nil || !ok {
			t.Fatalf("UpdateHeartbeat(%s): ok=%v err=%v", want, ok, err)
		}
		if got := ipOf(); got != want {
			t.Errorf("ip_address = %q, want %q", got, want)
		}
	}

	if _, err := repo.UpdateHeartbeat(ctx, id, sensor.HeartbeatUpdate{TenantID: &tenantID}); err != nil {
		t.Fatalf("UpdateHeartbeat without address: %v", err)
	}
	if got := ipOf(); got != "2606:4700:4700::1111" {
		t.Errorf("a heartbeat without an address overwrote ip_address with %q", got)
	}
}
