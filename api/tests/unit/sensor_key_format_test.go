package unit

// Sensor key formats (RFC-032 revision 2026-10-03): new keys are octs_ with
// a checksum, legacy rda_ keys keep authenticating until the sunset, and a
// sensor moves from rda_ to octs_ on renewal with an audit record.

import (
	"context"
	"errors"
	"strings"
	"testing"

	sensorsvc "github.com/openctemio/openctem/api/internal/app/sensor"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/sensorkey"
)

// legacyFixtureKey is a fake rda_ key in the legacy format (rda_ + 64 hex).
var legacyFixtureKey = "rda_" + strings.Repeat("0f", 32)

func seedLegacySensor(repo *sensorSvcMockRepo, svc *sensorsvc.SensorService) *sensor.Sensor {
	a := repo.seedSensor(shared.NewID(), "legacy-sensor", sensor.SensorTypeWorker)
	a.SetAPIKey(hashForTest(svc, legacyFixtureKey), legacyFixtureKey[:12])
	return a
}

func TestSensorKey_LegacyRDAKeyStillAuthenticates(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	a := seedLegacySensor(repo, svc)

	id, err := svc.AuthenticateIdentity(context.Background(), legacyFixtureKey)
	if err != nil {
		t.Fatalf("legacy rda_ key must keep authenticating: %v", err)
	}
	if id.Sensor.ID != a.ID || !id.PresentedLegacyKey() {
		t.Errorf("identity = %v, legacy %v", id.Sensor.ID, id.PresentedLegacyKey())
	}
	if !a.IsLegacyKey() {
		t.Error("a sensor on an rda_ key must report IsLegacyKey")
	}
}

func TestSensorKey_NewOCTSKeyAuthenticates(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	out, err := svc.CreateSensor(context.Background(), sensorsvc.CreateSensorInput{
		TenantID: shared.NewID().String(), Name: "octs-sensor", Type: "worker",
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := svc.AuthenticateIdentity(context.Background(), out.APIKey)
	if err != nil {
		t.Fatalf("new octs_ key must authenticate: %v", err)
	}
	if id.PresentedLegacyKey() || id.Sensor.IsLegacyKey() {
		t.Error("an octs_ key must not be reported as legacy")
	}
}

// A mistyped octs_ key and an enrollment token are refused offline: no hash
// lookup is made for them.
func TestSensorKey_MalformedOCTSRejectedBeforeLookup(t *testing.T) {
	repo := newSensorSvcMockRepo()
	svc := newSensorSvcTestService(repo)
	out, err := svc.CreateSensor(context.Background(), sensorsvc.CreateSensorInput{
		TenantID: shared.NewID().String(), Name: "octs-sensor", Type: "worker",
	})
	if err != nil {
		t.Fatal(err)
	}
	last := out.APIKey[len(out.APIKey)-1]
	swap := byte('a')
	if last == 'a' {
		swap = 'b'
	}
	enroll, _ := sensorkey.New(sensorkey.PrefixEnrollmentToken)
	for name, bad := range map[string]string{
		"checksum broken":  out.APIKey[:len(out.APIKey)-1] + string(swap),
		"truncated":        out.APIKey[:30],
		"enrollment token": enroll,
	} {
		before := repo.getByAPIKeyHashCalls
		_, err := svc.AuthenticateIdentity(context.Background(), bad)
		if !errors.Is(err, shared.ErrUnauthorized) {
			t.Errorf("%s: err = %v, want unauthorized", name, err)
		}
		if repo.getByAPIKeyHashCalls != before {
			t.Errorf("%s: a malformed key reached the hash lookup", name)
		}
	}
}

// The renewal that moves a sensor from rda_ to octs_ is recorded in the audit
// log, without key material.
func TestSensorKey_RenewalFromLegacyIsAudited(t *testing.T) {
	auditSvc, auditRepo := newTestAuditService()
	repo := newSensorSvcMockRepo()
	svc := sensorsvc.NewSensorService(repo, auditSvc, logger.NewNop())
	seedLegacySensor(repo, svc)

	id, err := svc.AuthenticateIdentity(context.Background(), legacyFixtureKey)
	if err != nil {
		t.Fatal(err)
	}
	newKey, _, err := svc.RenewAPIKey(context.Background(), id)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if p, ok := sensorkey.Valid(newKey); !ok || p != sensorkey.PrefixSensorKey {
		t.Fatalf("renewed key %q is not a valid octs_ key", newKey)
	}
	if _, err := svc.AuthenticateIdentity(context.Background(), newKey); err != nil {
		t.Fatalf("renewed octs_ key must authenticate: %v", err)
	}
	fresh, _ := repo.GetByID(context.Background(), id.Sensor.ID)
	if fresh.IsLegacyKey() {
		t.Error("after renewal the sensor must no longer be on a legacy key")
	}

	ev := auditRepo.lastCreated
	if ev == nil || ev.Action() != auditdom.ActionSensorKeyRenewed {
		t.Fatalf("expected a %s audit event", auditdom.ActionSensorKeyRenewed)
	}
	md := ev.Metadata()
	if md["upgraded_from_legacy_key"] != true || md["previous_key_format"] != "rda" || md["key_format"] != "octs" {
		t.Errorf("audit metadata = %v", md)
	}
	for k, v := range md {
		if s, ok := v.(string); ok && (strings.Contains(s, "octs_") || strings.Contains(s, "rda_")) {
			t.Errorf("audit metadata %q carries key material: %q", k, s)
		}
	}

	// A renewal from an octs_ key is not an upgrade.
	id2, err := svc.AuthenticateIdentity(context.Background(), newKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.RenewAPIKey(context.Background(), id2); err != nil {
		t.Fatal(err)
	}
	if md := auditRepo.lastCreated.Metadata(); md["upgraded_from_legacy_key"] != false || md["previous_key_format"] != "octs" {
		t.Errorf("octs_ renewal metadata = %v", md)
	}
}
