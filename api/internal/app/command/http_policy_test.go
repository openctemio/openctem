package command

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeHTTPPolicy struct {
	pol sensordom.ToolHTTPPolicy
	err error
}

func (f fakeHTTPPolicy) ToolHTTPPolicy(context.Context, shared.ID) (sensordom.ToolHTTPPolicy, error) {
	return f.pol, f.err
}

// Every scan command leaves with the organization's tool HTTP layer as it
// is at delivery; the stored command is never changed; a value a command's
// creator put in http_policy is replaced (or removed when the organization
// sets none); other command types are untouched.
func TestDeliverSetsTheOrganizationHTTPPolicy(t *testing.T) {
	no := false
	tid := shared.NewID()
	scan := &commanddom.Command{ID: shared.NewID(), TenantID: tid, Type: commanddom.CommandTypeScan,
		Payload: json.RawMessage(`{"scanner":"nuclei","http_policy":{"user_agent":"from-the-creator"}}`)}
	other := &commanddom.Command{ID: shared.NewID(), TenantID: tid, Type: commanddom.CommandType("collect"), Payload: json.RawMessage(`{"a":1}`)}
	stored := string(scan.Payload)

	s := &Service{httpPolicy: fakeHTTPPolicy{pol: sensordom.ToolHTTPPolicy{UserAgent: "corp-scan", AllowInsecureTLS: &no}}}
	out, err := s.deliver(context.Background(), "sensor-1", []*commanddom.Command{scan, other}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Scanner    string                    `json:"scanner"`
		HTTPPolicy *sensordom.ToolHTTPPolicy `json:"http_policy"`
	}
	if err := json.Unmarshal(out[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.Scanner != "nuclei" || p.HTTPPolicy == nil || p.HTTPPolicy.UserAgent != "corp-scan" || p.HTTPPolicy.AllowInsecureTLS == nil || *p.HTTPPolicy.AllowInsecureTLS {
		t.Fatalf("delivered %s", out[0].Payload)
	}
	if string(scan.Payload) != stored || string(out[1].Payload) != `{"a":1}` {
		t.Fatal("a stored command or a non-scan command was changed")
	}

	// No organization policy: a creator's http_policy is removed.
	s.httpPolicy = fakeHTTPPolicy{}
	out, err = s.deliver(context.Background(), "sensor-1", []*commanddom.Command{scan}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0].Payload) != `{"scanner":"nuclei"}` {
		t.Fatalf("creator policy kept: %s", out[0].Payload)
	}

	// SECURITY: a policy that cannot be read fails the delivery (fail
	// closed) rather than sending the job without it.
	s.httpPolicy = fakeHTTPPolicy{err: errors.New("db down")}
	if _, err := s.deliver(context.Background(), "sensor-1", []*commanddom.Command{scan}, nil); err == nil {
		t.Fatal("delivered without the organization policy")
	}
}
