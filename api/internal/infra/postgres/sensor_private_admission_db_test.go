package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The own-sensor rule for private targets (RFC-054 §14, R5): a sensor
// qualifies when its reported local policy is enforced, allows private
// ranges and its kill switch is off; it must be the tenant's own, never a
// platform sensor. Without a sensor, every dispatchable own sensor must
// qualify (a legacy sensor without a policy keeps the zone rule).
func TestSensorPrivateTargetAdmission_DB(t *testing.T) {
	ctx := context.Background()
	db := openSensorDB(t)
	repo := NewSensorRepository(&DB{DB: db})
	org, other := shared.NewID(), shared.NewID()
	for _, id := range []shared.ID{org, other} {
		mustExec(t, db, `INSERT INTO tenants (id, name, slug) VALUES ($1,$2,$3)`, id.String(), "pa-"+id.String(), "pa-"+id.String())
		t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String()) })
	}
	now := time.Now()
	policy := func(id shared.ID, p string) {
		mustExec(t, db, `UPDATE sensors SET reported_local_policy = $2::jsonb WHERE id = $1`, id.String(), p)
	}
	const ok = `{"state":"enforced","summary":{"targets_allow":2,"targets_deny":0,"allow_private":true,"allow_custom_templates":false,"allow_interactsh":false}}`

	// No own sensor: refused.
	if got, err := repo.PrivateTargetAdmission(ctx, org, nil); err != nil || got {
		t.Fatalf("no sensors: %v %v", got, err)
	}
	a := seedSensor(ctx, t, db, org, "online", &now, "nmap", 0)
	policy(a, ok)
	if got, err := repo.PrivateTargetAdmission(ctx, org, nil); err != nil || !got {
		t.Fatalf("one qualifying sensor: %v %v", got, err)
	}
	if got, _ := repo.PrivateTargetAdmission(ctx, org, &a); !got {
		t.Fatal("the qualifying sensor itself is refused")
	}
	// Another tenant's sensor id never qualifies for this tenant.
	if got, _ := repo.PrivateTargetAdmission(ctx, other, &a); got {
		t.Fatal("another tenant's sensor qualified")
	}

	// A legacy sensor without a policy joins: unpinned work is refused (it
	// could take the job), the qualifying sensor still qualifies by itself.
	b := seedSensor(ctx, t, db, org, "online", &now, "nmap", 0)
	if got, _ := repo.PrivateTargetAdmission(ctx, org, nil); got {
		t.Fatal("unpinned admitted although a sensor without a local policy can claim")
	}
	if got, _ := repo.PrivateTargetAdmission(ctx, org, &b); got {
		t.Fatal("a sensor without a local policy qualified")
	}
	// Private ranges not allowed, or the kill switch on: no.
	policy(b, `{"state":"enforced","summary":{"targets_allow":1,"targets_deny":0,"allow_private":false,"allow_custom_templates":false,"allow_interactsh":false}}`)
	if got, _ := repo.PrivateTargetAdmission(ctx, org, &b); got {
		t.Fatal("allow_private false qualified")
	}
	policy(a, `{"state":"enforced","kill_switch":true,"summary":{"targets_allow":2,"targets_deny":0,"allow_private":true,"allow_custom_templates":false,"allow_interactsh":false}}`)
	if got, _ := repo.PrivateTargetAdmission(ctx, org, &a); got {
		t.Fatal("a stopped sensor qualified")
	}

	// A platform sensor never qualifies, whatever its policy says.
	policy(a, ok)
	mustExec(t, db, `UPDATE sensors SET is_platform_sensor = TRUE WHERE id = $1`, a.String())
	if got, _ := repo.PrivateTargetAdmission(ctx, org, &a); got {
		t.Fatal("a platform sensor qualified")
	}
}
