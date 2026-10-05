package unit

// An administrator regenerates a sensor's key (for example after a suspected
// leak) while a renewal that authenticated with the old key is in flight. The
// renewal must not mint a key afterwards: the credential the administrator
// killed would otherwise be renewed into a valid one.

import (
	"context"
	"errors"
	"testing"
	"time"

	app "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestSensorService_RenewAPIKey_RegenerationBeforeRotate_Refused(t *testing.T) {
	cases := []struct {
		name      string
		ttl       time.Duration
		viaKeyRow bool // renew with a key row issued by an earlier renewal
	}{
		{name: "overlap, inline key presented", ttl: time.Hour},
		{name: "overlap, key row presented", ttl: time.Hour, viaKeyRow: true},
		{name: "no TTL, inline key presented"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			auditSvc, auditRepo := newTestAuditService()
			repo := newSensorSvcMockRepo()
			keyRepo := newMockSensorAPIKeyRepo(repo)
			svc := app.NewSensorService(repo, auditSvc, logger.NewNop())
			svc.SetKeyTTL(tc.ttl)
			svc.SetAPIKeyRepository(keyRepo)
			tenantID := shared.NewID()

			out, err := svc.CreateSensor(ctx, app.CreateSensorInput{
				TenantID: tenantID.String(), Name: "regen-race", Type: "worker",
			})
			if err != nil {
				t.Fatalf("create sensor: %v", err)
			}
			presented := out.APIKey
			if tc.viaKeyRow {
				ident, err := svc.AuthenticateIdentity(ctx, presented)
				if err != nil {
					t.Fatalf("authenticate: %v", err)
				}
				if presented, _, err = svc.RenewAPIKey(ctx, ident); err != nil {
					t.Fatalf("first renewal: %v", err)
				}
			}

			// The renewal authenticates with the (soon leaked-and-killed) key.
			ident, err := svc.AuthenticateIdentity(ctx, presented)
			if err != nil {
				t.Fatalf("authenticate: %v", err)
			}
			if tc.viaKeyRow && ident.KeyID == nil {
				t.Fatal("expected the renewal to authenticate through a key row")
			}

			// The administrator regenerates between that authentication and
			// the renewal's rotation.
			var adminKey string
			var regenErr error
			keyRepo.beforeRotate = func() {
				adminKey, regenErr = svc.RegenerateAPIKey(ctx, tenantID.String(), out.Sensor.ID.String(), nil)
			}
			auditBefore := auditRepo.createCalls

			renewed, _, err := svc.RenewAPIKey(ctx, ident)
			if regenErr != nil {
				t.Fatalf("regenerate: %v", regenErr)
			}
			if adminKey == "" {
				t.Fatal("the regeneration did not run before the rotation")
			}
			if err == nil {
				t.Fatal("a renewal that authenticated before the regeneration minted a key after it")
			}
			if !errors.Is(err, shared.ErrUnauthorized) {
				t.Errorf("renewal error = %v, want unauthorized", err)
			}
			if renewed != "" {
				t.Error("a refused renewal returned a key")
			}

			// Only the administrator's key works; no key row was minted.
			if n, _ := keyRepo.CountActiveBySensorID(ctx, out.Sensor.ID); n != 0 {
				t.Errorf("%d active key rows after the refused renewal, want 0", n)
			}
			if _, err := svc.AuthenticateIdentity(ctx, adminKey); err != nil {
				t.Errorf("the regenerated key must authenticate: %v", err)
			}
			if _, err := svc.AuthenticateIdentity(ctx, presented); err == nil {
				t.Error("the key the administrator replaced still authenticates")
			}

			// The refusal is a security signal: it is audited.
			if auditRepo.createCalls <= auditBefore {
				t.Fatal("the refused renewal wrote no audit event")
			}
			if got := string(auditRepo.lastCreated.Action()); got != "sensor.key_renewal_refused" {
				t.Errorf("last audit action = %q, want sensor.key_renewal_refused", got)
			}
		})
	}
}
