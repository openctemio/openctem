package scan

// System authority of platform policies (continuous coverage, automatic
// enrichment): their runs have no actor. The run records its policy, the
// dispatch gate and the claim re-check act with that policy's explicit
// authority (scope entries and tier, never a member's act scope), and a
// missing actor without a policy is refused instead of read as unrestricted.
// Architecture: docs/architecture/system-actors.md.

import (
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PolicyTriggerPrefix starts the triggered_by of a run a platform policy
// started ("policy:coverage"); it is not a user id.
const PolicyTriggerPrefix = "policy:"

// systemPolicyOf is the platform policy that owns sc ("" for a person's
// scan): the explicit system authority its runs act with.
func systemPolicyOf(sc *scan.Scan) string { return string(sc.ManagedBy) }

// actorOf is the person a scan's own act scope falls back to (its owner);
// a managed scan has none: it acts as its policy.
func actorOf(sc *scan.Scan) *shared.ID {
	if sc.IsManaged() {
		return nil
	}
	return sc.CreatedBy
}

// RunSystemPolicy is the platform policy a run belongs to ("" for a run of a
// person or an automation), as the trigger recorded it.
func RunSystemPolicy(run *scanrun.Run) string {
	p, _ := run.Context[RunContextKeySystemPolicy].(string)
	if !ValidSystemPolicy(p) {
		return ""
	}
	return p
}

// CommandPriorityOf is the queue class of a run's commands, by who started
// it: a platform policy's runs are low, a person's own start (Run now, quick
// scan, an approved run) is high, and everything else (schedules, automations,
// retries, asset discovery) is normal. The claim ranks by class with aging,
// so a policy's work waits behind a person's but is never starved.
func CommandPriorityOf(run *scanrun.Run) command.CommandPriority {
	if RunSystemPolicy(run) != "" {
		return command.CommandPriorityLow
	}
	if run.TriggerType == scanworkflow.TriggerTypeManual && userIDPtr(run.TriggeredBy) != nil {
		return command.CommandPriorityHigh
	}
	return command.CommandPriorityNormal
}

// stampRunAuthority records who a run acts as in its context. The caller's
// context never decides it: a managed scan's run carries its policy (and no
// actor); any other run carries the person who triggered it, else the scan's
// owner, when recordActor is set (the single-scanner path derives its actor
// at dispatch from the run and the scan instead).
func stampRunAuthority(runContext map[string]any, sc *scan.Scan, triggeredBy string, recordActor bool) {
	delete(runContext, RunContextKeyActor)
	delete(runContext, RunContextKeySystemPolicy)
	if policy := systemPolicyOf(sc); policy != "" {
		runContext[RunContextKeySystemPolicy] = policy
		return
	}
	if !recordActor {
		return
	}
	if actor := userIDPtr(triggeredBy); actor != nil {
		runContext[RunContextKeyActor] = actor.String()
	} else if sc.CreatedBy != nil {
		runContext[RunContextKeyActor] = sc.CreatedBy.String()
	}
}
