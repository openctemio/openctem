package unit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/command"
	commanddom "github.com/openctemio/openctem/server/pkg/domain/command"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// A payload over the cap is not created as one command: the producer gets a
// validation error and nothing is stored (docs/architecture/job-dispatch.md,
// "Payload size").
func TestCommandService_CreateRefusesAnOversizedPayload(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)

	// {"targets":["aaaa…"]} just over the cap.
	big := bytes.Repeat([]byte("a"), commanddom.MaxPayloadBytes)
	payload, _ := json.Marshal(map[string]any{"scanner": "nuclei", "targets": []string{string(big)}})
	before := commanddom.PayloadsRefused()
	_, err := svc.Create(context.Background(), command.CreateInput{
		TenantID: newCmdTestTenantID(), Type: "scan", Priority: "normal", Payload: payload})
	if !errors.Is(err, commanddom.ErrPayloadTooLarge) || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err = %v, want ErrPayloadTooLarge (validation)", err)
	}
	if len(repo.commands) != 0 {
		t.Fatalf("%d commands stored", len(repo.commands))
	}
	if commanddom.PayloadsRefused() != before+1 {
		t.Fatal("refusal not counted")
	}

	// At the cap it is created.
	ok := bytes.Repeat([]byte("1"), commanddom.MaxPayloadBytes)
	if _, err := svc.Create(context.Background(), command.CreateInput{
		TenantID: newCmdTestTenantID(), Type: "scan", Priority: "normal", Payload: ok}); err != nil {
		t.Fatalf("payload at the cap refused: %v", err)
	}
}
