package unit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/internal/app/template"
	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Poll hands a sensor its scan commands with the custom templates sealed in
// a manifest for that sensor, the command and its tenant; the stored command
// is not changed.
func TestCommandService_PollSignsCustomTemplates(t *testing.T) {
	master := make([]byte, 32)
	keys, err := scannertemplate.NewKeyring(master)
	if err != nil {
		t.Fatal(err)
	}
	repo := newCmdMockRepo()
	svc := command.NewService(repo, newCmdTestLogger(),
		command.WithTemplateSigner(template.NewPayloadSigner(keys, newCmdTestLogger())))

	tenantID := newCmdTestTenantID()
	body := "id: probe\ninfo:\n  name: probe\n  author: x\n  severity: info\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n"
	payload, _ := json.Marshal(map[string]any{
		"scanner": "nuclei", "target": "https://203.0.113.10",
		"custom_templates": []map[string]any{{
			"id": "t1", "name": "probe.yaml", "template_type": "nuclei",
			"content": base64.StdEncoding.EncodeToString([]byte(body)),
		}},
	})
	cmd, err := svc.Create(context.Background(), command.CreateInput{TenantID: tenantID, Type: "scan", Payload: payload})
	if err != nil {
		t.Fatal(err)
	}

	sensorID := shared.NewID().String()
	cmds, err := svc.Poll(context.Background(), command.PollInput{TenantID: tenantID, SensorID: sensorID, Limit: 10})
	if err != nil || len(cmds) != 1 {
		t.Fatalf("poll: %v, %d commands", err, len(cmds))
	}
	var got struct {
		Env *scannertemplate.Envelope `json:"custom_templates_envelope"`
	}
	if err := json.Unmarshal(cmds[0].Payload, &got); err != nil || got.Env == nil {
		t.Fatalf("polled payload has no signed manifest: %s", cmds[0].Payload)
	}
	var m scannertemplate.Manifest
	if err := json.Unmarshal(got.Env.Payload, &m); err != nil {
		t.Fatal(err)
	}
	if m.TenantID != tenantID || m.SensorID != sensorID || m.CommandID != cmd.ID.String() {
		t.Fatalf("manifest bound to %q/%q/%q, want %q/%q/%q", m.TenantID, m.SensorID, m.CommandID, tenantID, sensorID, cmd.ID)
	}
	if string(repo.commands[cmd.ID.String()].Payload) != string(payload) {
		t.Fatal("the stored command was changed")
	}
}
