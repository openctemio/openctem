package sensor_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/crypto"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// keyBoundOnly is an organization identity policy that refuses bearer keys.
type keyBoundOnly struct{}

func (keyBoundOnly) BearerKeysAllowed(context.Context, shared.ID) (bool, error) { return false, nil }
func (keyBoundOnly) SetBearerKeysAllowed(context.Context, shared.ID, bool) (bool, error) {
	return false, nil
}
func (keyBoundOnly) KeyBindRequiresApproval(context.Context, shared.ID) (bool, error) {
	return false, nil
}
func (keyBoundOnly) SetKeyBindRequiresApproval(context.Context, shared.ID, bool) (bool, error) {
	return false, nil
}

// An organization that requires key-bound identity mints no bearer keys: an
// administrator regenerating an existing bearer sensor key is refused like a
// new bearer-key sensor, and the existing key keeps working until it is
// replaced by pairing (sensor → platform review, key policies).
func TestSensorRegenerate_RefusedWhenKeyBoundRequired_DB(t *testing.T) {
	h := newActivityHarness(t)
	tid := h.tenant()
	svc := newPepperedService(h, "")
	inline := "rda_" + strings.Repeat("7c", 32)
	id := h.sensorWithKey(tid, crypto.HashTokenPeppered(inline, testEncryptionKey))
	svc.SetIdentityPolicyRepository(keyBoundOnly{})

	key, err := svc.RegenerateAPIKey(context.Background(), tid.String(), id.String(), nil)
	if !errors.Is(err, sensordom.ErrBearerKeysDisabled) || key != "" {
		t.Fatalf("regenerate under a key-bound-only policy: key %q, err %v; want ErrBearerKeysDisabled", key, err)
	}
	if _, err := svc.AuthenticateIdentity(context.Background(), inline); err != nil {
		t.Fatalf("the existing key must be untouched: %v", err)
	}
}
