package command

import (
	"bytes"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func TestNewCommand_PayloadCap(t *testing.T) {
	tid := shared.NewID()
	if _, err := NewCommand(tid, CommandTypeScan, CommandPriorityNormal, bytes.Repeat([]byte("1"), MaxPayloadBytes)); err != nil {
		t.Fatalf("payload at the cap: %v", err)
	}
	_, err := NewCommand(tid, CommandTypeScan, CommandPriorityNormal, bytes.Repeat([]byte("1"), MaxPayloadBytes+1))
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("payload over the cap: %v", err)
	}
	if MaxPayloadBytes >= 10<<20 {
		t.Fatal("the cap must stay well under the sensor's 10 MiB poll limit")
	}
}
