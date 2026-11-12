package command

import (
	"testing"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
)

// The class of a failure: the sensor's class first, then its error code,
// then (a sensor that sent neither) the text. A target-side class, a code
// that names another kind of failure and a permanent failure stop the
// search.
func TestInfraClassOf_Precedence(t *testing.T) {
	cases := []struct {
		name  string
		in    FailInput
		msg   string
		want  commanddom.FailureClass
		moved bool
	}{
		{"class wins over a text of another kind", FailInput{Infra: &InfraReport{Class: "infra.resource.disk"}}, "tool crashed", commanddom.ClassResourceDisk, true},
		{"target class", FailInput{Infra: &InfraReport{Class: "target.edge_blocked"}}, "executable file not found", "target.edge_blocked", false},
		{"error code", FailInput{Infra: &InfraReport{ErrorCode: "TOOL_UNAVAILABLE"}}, "x", commanddom.ClassToolUnavailable, true},
		{"class spelling in the code", FailInput{Infra: &InfraReport{ErrorCode: "infra.tool_crashed"}}, "x", commanddom.ClassToolCrashed, true},
		{"TOOL_EXIT is the sensor's verdict", FailInput{Infra: &InfraReport{ErrorCode: "TOOL_EXIT"}}, "tool crashed", "", false},
		{"TIMEOUT", FailInput{Infra: &InfraReport{ErrorCode: "TIMEOUT"}}, "out of memory", "", false},
		{"text fallback without a class", FailInput{}, "write: no space left on device", commanddom.ClassResourceDisk, true},
		{"text fallback with the generic code", FailInput{Infra: &InfraReport{ErrorCode: "COMMAND_FAILED"}}, "out of memory", commanddom.ClassResourceMemory, true},
		{"permanent failure is not infrastructure", FailInput{}, "scanner not found: executable file not found", "", false},
		{"plain failure", FailInput{}, "scan failed", "", false},
	}
	for _, c := range cases {
		got, _, ok := infraClassOf(c.in, c.msg)
		if c.moved && got != c.want {
			t.Errorf("%s: class %q, want %q", c.name, got, c.want)
		}
		if !c.moved && ok && got.Movable() {
			t.Errorf("%s: movable class %q, want none", c.name, got)
		}
	}
}
