package sensor_test

// An administrator's key regeneration racing a sensor's renewal, against a
// migrated database. The renewal authenticated with the old key before the
// regeneration; whichever runs first, the old key must not come out of the
// race renewed into a valid credential.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// validKeys counts the sensor's credentials that authenticate now: active,
// unrevoked, unexpired key rows plus an unexpired inline key.
func (h *activityHarness) validKeys(id shared.ID) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRowContext(context.Background(), `
		SELECT (SELECT COUNT(*) FROM sensor_api_keys
		         WHERE sensor_id = $1 AND is_active AND revoked_at IS NULL
		           AND (expires_at IS NULL OR expires_at > NOW()))
		     + (SELECT COUNT(*) FROM sensors
		         WHERE id = $1 AND (key_expires_at IS NULL OR key_expires_at > NOW()))`,
		id.String()).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// Each round a renewal (already authenticated with the old key) and an admin
// regeneration start together. Afterwards the only valid credential is the
// regenerated key: a renewal that committed first had its key revoked by the
// regeneration, and one that came second was refused.
func TestSensorRegenerate_RacingRenewal_OnlyAdminKeyValid_DB(t *testing.T) {
	h := newActivityHarness(t)
	tid := h.tenant()
	ctx := context.Background()
	svc := newPepperedService(h, "")
	svc.SetKeyTTL(90 * 24 * time.Hour)

	works := func(key string) bool {
		_, err := svc.AuthenticateIdentity(ctx, key)
		return err == nil
	}

	const rounds = 100
	renewedFirst, refused := 0, 0
	for r := 0; r < rounds; r++ {
		inline := "rda_" + fmt.Sprintf("%02x", r) + strings.Repeat("8d", 31)
		id := h.sensorWithKey(tid, crypto.HashTokenPeppered(inline, testEncryptionKey))

		// Odd rounds renew with a key row issued by an earlier renewal.
		presented := inline
		if r%2 == 1 {
			ident, err := svc.AuthenticateIdentity(ctx, inline)
			if err != nil {
				t.Fatal(err)
			}
			if presented, _, err = svc.RenewAPIKey(ctx, ident); err != nil {
				t.Fatalf("round %d: first renewal: %v", r, err)
			}
		}
		ident, err := svc.AuthenticateIdentity(ctx, presented)
		if err != nil {
			t.Fatalf("round %d: authenticate: %v", r, err)
		}

		var (
			wg                 sync.WaitGroup
			start              = make(chan struct{})
			adminKey, renewed  string
			regenErr, renewErr error
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			adminKey, regenErr = svc.RegenerateAPIKey(ctx, tid.String(), id.String(), nil)
		}()
		go func() {
			defer wg.Done()
			<-start
			renewed, _, renewErr = svc.RenewAPIKey(ctx, ident)
		}()
		close(start)
		wg.Wait()

		if regenErr != nil {
			t.Fatalf("round %d: regenerate: %v", r, regenErr)
		}
		if renewErr == nil {
			renewedFirst++
			if works(renewed) {
				t.Errorf("round %d: the renewal's key survived the regeneration", r)
			}
		} else {
			refused++
		}
		if !works(adminKey) {
			t.Errorf("round %d: the regenerated key does not authenticate", r)
		}
		if works(presented) {
			t.Errorf("round %d: the key the administrator replaced still authenticates", r)
		}
		if got := h.validKeys(id); got != 1 {
			t.Errorf("round %d: %d valid credentials after the race, want 1 (the regenerated key)", r, got)
		}
	}
	t.Logf("%d rounds: the renewal committed first in %d, was refused in %d", rounds, renewedFirst, refused)
}

// A renewal that authenticated with a key before the administrator
// regenerated it is refused when it runs afterwards, whether it presented the
// inline key or a key row, and no key is minted.
func TestSensorRegenerate_LateRenewalWithRevokedKey_Refused_DB(t *testing.T) {
	h := newActivityHarness(t)
	tid := h.tenant()
	ctx := context.Background()
	svc := newPepperedService(h, "")
	svc.SetKeyTTL(90 * 24 * time.Hour)

	for _, viaKeyRow := range []bool{false, true} {
		inline := "rda_" + strings.Repeat("9e", 32)
		if viaKeyRow {
			inline = "rda_" + strings.Repeat("af", 32)
		}
		id := h.sensorWithKey(tid, crypto.HashTokenPeppered(inline, testEncryptionKey))
		presented := inline
		if viaKeyRow {
			ident, err := svc.AuthenticateIdentity(ctx, inline)
			if err != nil {
				t.Fatal(err)
			}
			if presented, _, err = svc.RenewAPIKey(ctx, ident); err != nil {
				t.Fatalf("first renewal: %v", err)
			}
		}
		ident, err := svc.AuthenticateIdentity(ctx, presented)
		if err != nil {
			t.Fatal(err)
		}
		adminKey, err := svc.RegenerateAPIKey(ctx, tid.String(), id.String(), nil)
		if err != nil {
			t.Fatalf("regenerate: %v", err)
		}

		next, _, err := svc.RenewAPIKey(ctx, ident)
		if err == nil {
			t.Errorf("key row %v: a renewal with the revoked key was accepted", viaKeyRow)
			if _, err := svc.AuthenticateIdentity(ctx, next); err == nil {
				t.Errorf("key row %v: the revoked key was renewed into a valid one", viaKeyRow)
			}
		}
		if got := h.validKeys(id); got != 1 {
			t.Errorf("key row %v: %d valid credentials, want 1 (the regenerated key)", viaKeyRow, got)
		}
		if _, err := svc.AuthenticateIdentity(ctx, adminKey); err != nil {
			t.Errorf("key row %v: the regenerated key must authenticate: %v", viaKeyRow, err)
		}
	}
}
