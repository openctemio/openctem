package sensor_test

// A sensor of a suspended organization is refused on the bearer-key path
// (inline key and the multi-key store share the check), against a migrated
// database (docs/architecture/organization-suspension.md).

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/suspension"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func TestSensorOfSuspendedOrganizationRefused_DB(t *testing.T) {
	h := newActivityHarness(t)
	ctx := context.Background()
	db := &postgres.DB{DB: h.db}
	store := postgres.NewOrganizationStatusRepository(db)

	tid := h.tenant()
	key := "rda_" + strings.Repeat("5a", 32)
	sensorID := h.sensorWithKey(tid, crypto.HashTokenPeppered(key, testEncryptionKey))

	svc := newPepperedService(h, "")
	svc.SetOrganizationGate(suspension.NewGate(store, nil, nil))

	if id, err := svc.AuthenticateIdentity(ctx, key); err != nil || id.Sensor == nil || id.Sensor.ID != sensorID {
		t.Fatalf("active organization: %v", err)
	}
	if ok, err := store.Suspend(ctx, tid, nil, "abuse", time.Now()); err != nil || !ok {
		t.Fatalf("suspend: %v %v", ok, err)
	}
	_, err := svc.AuthenticateIdentity(ctx, key)
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != tenantdom.CodeOrganizationSuspended || !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("suspended organization: %v, want %s (forbidden)", err, tenantdom.CodeOrganizationSuspended)
	}
	if ok, err := store.Unsuspend(ctx, tid); err != nil || !ok {
		t.Fatalf("unsuspend: %v %v", ok, err)
	}
	if _, err := svc.AuthenticateIdentity(ctx, key); err != nil {
		t.Fatalf("after lift: %v", err)
	}
}
