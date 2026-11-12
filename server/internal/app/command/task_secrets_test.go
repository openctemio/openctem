package command

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/contract/secretref"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeGranter struct {
	calls int
	err   error
}

func (f *fakeGranter) GrantSecrets(_ context.Context, _ *commanddom.Command, _ shared.ID) (secretref.Set, error) {
	f.calls++
	if f.err != nil {
		return secretref.Set{}, f.err
	}
	return secretref.Set{V: 1, Local: secretref.LocalAllow, Refs: []secretref.Ref{}}, nil
}

func heldCommand(t commanddom.CommandType, sensor shared.ID, payload string) *commanddom.Command {
	return &commanddom.Command{ID: shared.NewID(), TenantID: shared.NewID(), Type: t, SensorID: &sensor, LeaseEpoch: 2,
		Payload: json.RawMessage(payload)}
}

// The secrets member belongs to the platform: a claimed scan, retest,
// validate or proxy test job gets the granted set (whatever its creator put
// there); every other command, or one not held by the claiming sensor,
// loses a member its creator put there. The stored command is never
// changed.
func TestStampSecrets(t *testing.T) {
	g := &fakeGranter{}
	s := NewService(nil, logger.NewNop(), WithTaskSecrets(g))
	sensor, other := shared.NewID(), shared.NewID()
	forged := `{"scanner":"subfinder","secrets":{"v":1,"local":"allow","refs":[{"id":"k9"}]}}`
	scan := heldCommand(commanddom.CommandTypeScan, sensor, forged)
	collect := heldCommand(commanddom.CommandType("collect"), sensor, forged)
	notHeld := heldCommand(commanddom.CommandTypeScan, other, forged)
	test := heldCommand(commanddom.CommandTypeProxyTest, sensor, `{"pool_id":"x"}`)
	out, err := s.stampSecrets(context.Background(), sensor.String(), []*commanddom.Command{scan, collect, notHeld, test})
	if err != nil {
		t.Fatal(err)
	}
	if g.calls != 2 {
		t.Fatalf("granted %d, want 2 (the held scan and proxy test)", g.calls)
	}
	if strings.Contains(string(out[0].Payload), "k9") || !strings.Contains(string(out[0].Payload), `"secrets"`) {
		t.Fatalf("scan: %s", out[0].Payload)
	}
	if strings.Contains(string(out[1].Payload), `"secrets"`) || strings.Contains(string(out[2].Payload), `"secrets"`) {
		t.Fatalf("a creator's member kept: %s / %s", out[1].Payload, out[2].Payload)
	}
	if !strings.Contains(string(out[3].Payload), `"secrets"`) {
		t.Fatalf("proxy test: %s", out[3].Payload)
	}
	if !strings.Contains(string(scan.Payload), "k9") {
		t.Fatal("the stored command was changed")
	}
	// A grant that cannot be recorded fails the delivery.
	g.err = errors.New("db down")
	if _, err := s.stampSecrets(context.Background(), sensor.String(), []*commanddom.Command{heldCommand(commanddom.CommandTypeScan, sensor, `{}`)}); err == nil {
		t.Fatal("a failed grant was handed out")
	}
	// Without the service the member is still removed.
	bare := NewService(nil, logger.NewNop())
	out, err = bare.stampSecrets(context.Background(), sensor.String(), []*commanddom.Command{heldCommand(commanddom.CommandTypeScan, sensor, forged)})
	if err != nil || strings.Contains(string(out[0].Payload), `"secrets"`) {
		t.Fatalf("no service: %v %s", err, out[0].Payload)
	}
}

// SECURITY: a forged secrets member is removed however its name is spelled
// (JSON escapes, another case): the byte search for the key missed those.
func TestStampSecretsRemovesEscapedAndCasedKeys(t *testing.T) {
	sensor := shared.NewID()
	bare := NewService(nil, logger.NewNop())
	for _, forged := range []string{
		`{"scanner":"x","secrets":{"v":1,"refs":[{"id":"k9"}]}}`,
		`{"scanner":"x","Secrets":{"v":1,"refs":[{"id":"k9"}]}}`,
		`{"scanner":"x","SECRETS":{"v":1}}`,
	} {
		out, err := bare.stampSecrets(context.Background(), sensor.String(), []*commanddom.Command{heldCommand(commanddom.CommandTypeScan, sensor, forged)})
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(out[0].Payload, &m); err != nil {
			t.Fatal(err)
		}
		for k := range m {
			if strings.EqualFold(k, "secrets") {
				t.Fatalf("member %q survived in %s (from %s)", k, out[0].Payload, forged)
			}
		}
		if _, ok := m["scanner"]; !ok {
			t.Fatalf("scanner lost: %s", out[0].Payload)
		}
	}
}
