package postgres

// The isolation level of a job: a job of a tool that needs strong isolation
// carries the sensor feature isolation.strong@1 (command.PayloadKeyRequiredFeatures),
// which the claim predicates match against what the sensor itself reported.
// It is stamped where every command is created, so no dispatch path (scan,
// retest, validate, follow-up, host split) can leave it out.

import (
	"fmt"

	"github.com/openctemio/openctem/server/pkg/domain/command"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
)

// SetStrongIsolationTools says which tools need strong isolation. Production
// wires none yet: no bundled tool asks for it.
func (r *CommandRepository) SetStrongIsolationTools(f command.StrongIsolationTools) {
	r.strongTools = f
}

// requireIsolation adds isolation.strong@1 to the required features of a job
// whose tool needs strong isolation. The job is stored and waits; it is
// never refused here and never offered to a sensor that did not report the
// capability.
func (r *CommandRepository) requireIsolation(cmd *command.Command) error {
	if r.strongTools == nil {
		return nil
	}
	tool := command.JobTool(cmd)
	if tool == "" || !r.strongTools(tool) {
		return nil
	}
	if err := command.RequireFeature(cmd, sensor.CapabilityIsolationStrong); err != nil {
		return fmt.Errorf("require strong isolation for %s: %w", tool, err)
	}
	return nil
}
