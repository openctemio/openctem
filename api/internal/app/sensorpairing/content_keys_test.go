package sensorpairing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	contentdom "github.com/openctemio/openctem/api/pkg/domain/contentpack"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/jobsign"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// An approved identity carries the content keys the sensor pins: the
// platform's for every sensor, the organization's own only for a sensor of
// that organization, never for a shared sensor and never another
// organization's. The key id is the job-signing form (SHA256:<hex>) and
// recomputes from the key.
func TestIdentityCarriesContentKeys(t *testing.T) {
	signer, err := contentdom.NewSigner(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{contentKeys: signer, log: logger.NewNop()}
	tenantA, tenantB := shared.NewID(), shared.NewID()
	instanceToken := shared.NewID()

	platPub, _, _ := signer.PlatformPublicKey()
	pubA, _, _ := signer.PublicKey(tenantA.String())
	pubB, _, _ := signer.PublicKey(tenantB.String())

	check := func(name string, keys []string, want ed25519.PublicKey) {
		t.Helper()
		if len(keys) != 1 {
			t.Fatalf("%s: %d keys, want 1", name, len(keys))
		}
		if keys[0] != base64.StdEncoding.EncodeToString(want) {
			t.Errorf("%s: wrong key", name)
		}
	}

	own := s.contentSigning(&sensordom.Pairing{TenantID: &tenantA})
	if own == nil || len(own.Platform) != 1 || len(own.Tenant) != 1 {
		t.Fatalf("organization sensor: %+v", own)
	}
	check("platform key", []string{own.Platform[0].PublicKey}, platPub)
	check("tenant key", []string{own.Tenant[0].PublicKey}, pubA)
	if own.Tenant[0].PublicKey == base64.StdEncoding.EncodeToString(pubB) {
		t.Fatal("organization A's sensor was given organization B's key")
	}
	for _, k := range []struct{ id, algo, pub string }{
		{own.Platform[0].KeyID, own.Platform[0].Algorithm, own.Platform[0].PublicKey},
		{own.Tenant[0].KeyID, own.Tenant[0].Algorithm, own.Tenant[0].PublicKey},
	} {
		if _, err := (jobsign.PublicKey{KeyID: k.id, Algorithm: k.algo, PublicKey: k.pub}).Decode(); err != nil {
			t.Errorf("a sensor would refuse the key it is given: %v", err)
		}
	}

	sharedKeys := s.contentSigning(&sensordom.Pairing{InstanceTokenID: &instanceToken})
	if sharedKeys == nil || len(sharedKeys.Platform) != 1 || len(sharedKeys.Tenant) != 0 {
		t.Fatalf("shared sensor: %+v, want the platform key only", sharedKeys)
	}
	// A pairing with both an instance token and a tenant (never created) is
	// still treated as shared.
	odd := s.contentSigning(&sensordom.Pairing{InstanceTokenID: &instanceToken, TenantID: &tenantA})
	if odd == nil || len(odd.Tenant) != 0 {
		t.Fatalf("instance pairing with a tenant: %+v", odd)
	}

	if (&Service{log: logger.NewNop()}).contentSigning(&sensordom.Pairing{TenantID: &tenantA}) != nil {
		t.Error("keys without a key source")
	}
}
