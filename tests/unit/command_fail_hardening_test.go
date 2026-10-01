package unit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/openctemio/api/internal/app/command"
	commanddom "github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/shared"
)

// ATTACK: any tenant sensor failing an unclaimed broadcast command (a cheap way
// to kill other sensors' work) is rejected.
func TestCommandFail_PendingUnassignedRejected(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()
	cmd := createTestCommand(t, svc, tenantID, "scan", "normal")

	_, err := svc.Fail(context.Background(), command.FailInput{
		TenantID: tenantID, SensorID: shared.NewID().String(), CommandID: cmd.ID.String(), ErrorMessage: "x",
	})
	if err == nil || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected validation error for failing an unclaimed command, got %v", err)
	}
	if repo.commands[cmd.ID.String()].Status != commanddom.CommandStatusPending {
		t.Fatal("unclaimed command must stay pending")
	}
}

// A pending command explicitly assigned to the calling sensor may be failed
// (the sensor rejecting a job it was handed).
func TestCommandFail_PendingAssignedToCallerAllowed(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()
	sensorID := shared.NewID()
	cmd, err := svc.Create(context.Background(), command.CreateInput{
		TenantID: tenantID, SensorID: sensorID.String(), Type: "scan", Priority: "normal",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	failed, err := svc.Fail(context.Background(), command.FailInput{
		TenantID: tenantID, SensorID: sensorID.String(), CommandID: cmd.ID.String(), ErrorMessage: "unsupported",
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if failed.Status != commanddom.CommandStatusFailed {
		t.Fatalf("status = %s", failed.Status)
	}
}

// A finished command cannot be flipped to failed; the conflict is ErrConflict
// (mapped to 409 by the handler), not a 500.
func TestCommandFail_FinishedCommandConflict(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()
	cmd := createTestCommand(t, svc, tenantID, "scan", "normal")
	repo.commands[cmd.ID.String()].Status = commanddom.CommandStatusCompleted

	_, err := svc.Fail(context.Background(), command.FailInput{
		TenantID: tenantID, CommandID: cmd.ID.String(), ErrorMessage: "late",
	})
	if !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
	if repo.commands[cmd.ID.String()].Status != commanddom.CommandStatusCompleted {
		t.Fatal("completed command must not be flipped to failed")
	}
}

func TestCommandFail_ErrorMessageIsBounded(t *testing.T) {
	repo := newCmdMockRepo()
	svc := newCmdTestService(repo)
	tenantID := newCmdTestTenantID()
	cmd := createTestCommand(t, svc, tenantID, "scan", "normal")
	_, _ = svc.Acknowledge(context.Background(), tenantID, "sensor-test", cmd.ID.String())

	huge := strings.Repeat("é", command.MaxFailErrorMessageBytes) // 2 bytes per rune
	failed, err := svc.Fail(context.Background(), command.FailInput{
		TenantID: tenantID, CommandID: cmd.ID.String(), ErrorMessage: huge,
	})
	if err != nil {
		t.Fatalf("fail: %v", err)
	}
	if len(failed.ErrorMessage) > command.MaxFailErrorMessageBytes {
		t.Fatalf("error message not capped: %d bytes", len(failed.ErrorMessage))
	}
	if !utf8.ValidString(failed.ErrorMessage) {
		t.Fatal("truncation split a UTF-8 rune")
	}
}
