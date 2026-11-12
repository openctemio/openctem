package command

// The size cap of a command payload (docs/architecture/job-dispatch.md,
// "Payload size"). A sensor reads at most 10 MiB from one commands poll
// answer, and a claim adds to the stored payload what it hands out (the
// organization's HTTP policy, program rules, settings layers, template
// signatures, secret refs and the signed job). One command over that limit
// stops the sensor's intake until it fails the command. Every producer builds
// its command with NewCommand, which refuses a payload over the cap with
// ErrPayloadTooLarge: the producer gets a clear error, and nothing is
// truncated or split silently. Producers that can split their work (the scan
// planner chunks targets) keep each job well under it.

import (
	"fmt"
	"sync/atomic"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// MaxPayloadBytes is the largest stored command payload: 4 MiB, well under
// the sensor's 10 MiB poll answer limit, so a claim that adds its delivery
// fields and the signature to the largest payload, next to other commands in
// the same answer, still fits.
const MaxPayloadBytes = 4 << 20

// ErrPayloadTooLarge is the error of a command whose payload is over
// MaxPayloadBytes. It is a validation error: the producer must split the work.
var ErrPayloadTooLarge = shared.NewDomainError("COMMAND_PAYLOAD_TOO_LARGE",
	"the command payload is larger than the platform sends to a sensor; split the work into smaller jobs (fewer targets per job)",
	shared.ErrValidation)

// payloadsRefused counts the commands refused for their payload size, for
// the metric (internal/metrics: command_payload_refused_total).
var payloadsRefused atomic.Uint64

// PayloadsRefused is how many commands were refused for their payload size
// since the process started.
func PayloadsRefused() uint64 { return payloadsRefused.Load() }

// CheckPayloadSize returns ErrPayloadTooLarge (wrapped with the size) when
// payload is over MaxPayloadBytes.
func CheckPayloadSize(payload []byte) error {
	if len(payload) <= MaxPayloadBytes {
		return nil
	}
	payloadsRefused.Add(1)
	return fmt.Errorf("%w (%d bytes, limit %d)", ErrPayloadTooLarge, len(payload), MaxPayloadBytes)
}
