package sealed

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/openctemio/contract/secretref"
)

// taskSecretsVector is the cross-implementation vector of a task secrets
// answer, shared with sdk-go (pkg/sealedmsg/testdata). Never regenerated.
type taskSecretsVector struct {
	PrivateKey  string `json:"private_key_b64url"`
	PublicKey   string `json:"public_key_b64url"`
	KeyID       string `json:"key_id"`
	SensorID    string `json:"sensor_id"`
	CommandID   string `json:"command_id"`
	LeaseEpoch  int64  `json:"lease_epoch"`
	RequestBody string `json:"request_body"`
	InfoHex     string `json:"info_hex"`
	Plaintext   string `json:"plaintext"`
	Sealed      string `json:"sealed_b64url"`
}

func loadTaskSecretsVector(t *testing.T) taskSecretsVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/task-secrets-vector-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v taskSecretsVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTaskSecretsVector(t *testing.T) {
	v := loadTaskSecretsVector(t)
	priv, err := ParsePrivateKey(b64(t, v.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	pub := b64(t, v.PublicKey)
	if !bytes.Equal(priv.Public().Bytes(), pub) || secretref.KeyID(pub) != v.KeyID {
		t.Fatal("vector key pair or key id does not match")
	}
	info := secretref.Info(v.SensorID, v.CommandID, v.LeaseEpoch, []byte(v.RequestBody))
	if hex.EncodeToString(info) != v.InfoHex {
		t.Fatalf("contract Info differs from the vector's info")
	}
	sealedBytes := b64(t, v.Sealed)
	pt, err := OpenWithKey(priv, info, sealedBytes)
	if err != nil || string(pt) != v.Plaintext {
		t.Fatalf("vector does not open: %v", err)
	}
	// One changed info byte, or one changed sealed byte, does not open.
	badInfo := bytes.Clone(info)
	badInfo[len(badInfo)-1] ^= 1
	if _, err := OpenWithKey(priv, badInfo, sealedBytes); !errors.Is(err, ErrOpen) {
		t.Fatalf("changed info opened: %v", err)
	}
	for _, i := range []int{0, len(sealedBytes) / 2, len(sealedBytes) - 1} {
		bad := bytes.Clone(sealedBytes)
		bad[i] ^= 1
		if _, err := OpenWithKey(priv, info, bad); !errors.Is(err, ErrOpen) {
			t.Fatalf("changed sealed byte %d opened: %v", i, err)
		}
	}
}

func TestSealToKeyBinding(t *testing.T) {
	reply, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"lease_epoch":3,"refs":["k1"],"reply_key":"x"}`)
	info := secretref.Info("s-1", "c-1", 3, body)
	ct, err := SealToKey(reply.Public().Bytes(), info, []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := OpenWithKey(reply, info, ct); err != nil || string(pt) != "value" {
		t.Fatalf("round trip: %q %v", pt, err)
	}
	for name, c := range map[string]struct {
		key  *PrivateKey
		info []byte
	}{
		"another key":     {other, info},
		"another sensor":  {reply, secretref.Info("s-2", "c-1", 3, body)},
		"another command": {reply, secretref.Info("s-1", "c-2", 3, body)},
		"another epoch":   {reply, secretref.Info("s-1", "c-1", 4, body)},
		"another body":    {reply, secretref.Info("s-1", "c-1", 3, append(bytes.Clone(body), ' '))},
	} {
		if _, err := OpenWithKey(c.key, c.info, ct); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
	if _, err := SealToKey([]byte("not a key"), info, []byte("v")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("bad reply key: %v", err)
	}
	if _, err := SealToKey(reply.Public().Bytes(), info, make([]byte, MaxReplyPlaintext+1)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("oversized plaintext: %v", err)
	}
}
