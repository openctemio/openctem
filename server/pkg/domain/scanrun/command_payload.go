package scanrun

// The keys a scan or workflow command must carry for a finished command to be
// routed back into its scan run.
//
// These are constants because the two sides drifted. The dispatcher wrote
// `run_id`; the command handler read `scan_run_id` and treated anything
// without it as "not a scan workflow command", returning silently. Every
// single-scanner run therefore went unreported: the real scanner error was
// dropped and the run sat until a reaper stamped it as a timeout. Nothing
// failed loudly, and no command in the production database ever carried the key
// the reader wanted.
//
// A literal on each side cannot be checked. A shared constant can, and
// TestStepCommandPayloadKeysMatchHandlerContract does.
const (
	// PayloadKeyScanRunID identifies the run a command belongs to.
	PayloadKeyScanRunID = "scan_run_id"
	// PayloadKeyStepKey identifies which step of that run the command is.
	PayloadKeyStepKey = "step_key"
	// PayloadKeyStepRunID identifies the specific step-run row.
	PayloadKeyStepRunID = "scan_run_step_id"
)

// StepCommandPayload is the progression contract embedded in a command payload.
//
// The reader side unmarshals into this shape. Both ScanRunID and StepKey are
// required — a payload missing either cannot be routed and the command's result
// is discarded.
type StepCommandPayload struct {
	ScanRunID string `json:"scan_run_id"`
	StepRunID string `json:"scan_run_step_id"`
	StepKey   string `json:"step_key"`
}

// IsRoutable reports whether the payload carries enough to reach a step.
func (p StepCommandPayload) IsRoutable() bool {
	return p.ScanRunID != "" && p.StepKey != ""
}
