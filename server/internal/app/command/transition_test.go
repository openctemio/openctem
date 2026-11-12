package command

import (
	"encoding/json"
	"testing"
	"time"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestSameJSON(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"", "", true},
		{"", "null", true},
		{"null", " ", true},
		{`{"a":1,"b":[1,2]}`, `{ "b":[1,2], "a":1 }`, true},
		{`{"a":1}`, `{"a":2}`, false},
		{`{"a":1}`, "", false},
		{"", `{}`, false},
		{`{bad`, `{bad`, false},
	} {
		if got := sameJSON(json.RawMessage(tc.a), json.RawMessage(tc.b)); got != tc.want {
			t.Errorf("sameJSON(%q, %q) = %v", tc.a, tc.b, got)
		}
	}
}

func TestTransitionAllowedTable(t *testing.T) {
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Minute)
	cmd := func(st commanddom.CommandStatus, exp *time.Time) *commanddom.Command {
		return &commanddom.Command{ID: shared.NewID(), Status: st, ExpiresAt: exp}
	}
	for _, tc := range []struct {
		name string
		t    Transition
		c    *commanddom.Command
		mine bool
		want bool
	}{
		{"claim pending", TransitionClaim, cmd(commanddom.CommandStatusPending, &future), false, true},
		{"claim expired", TransitionClaim, cmd(commanddom.CommandStatusPending, &past), false, false},
		{"start pending", TransitionStart, cmd(commanddom.CommandStatusPending, nil), true, false},
		{"fail pending unassigned", TransitionFail, cmd(commanddom.CommandStatusPending, nil), false, false},
		{"fail pending mine", TransitionFail, cmd(commanddom.CommandStatusPending, nil), true, true},
		{"start acknowledged", TransitionStart, cmd(commanddom.CommandStatusAcknowledged, nil), true, true},
		{"complete acknowledged", TransitionComplete, cmd(commanddom.CommandStatusAcknowledged, nil), true, false},
		{"complete running", TransitionComplete, cmd(commanddom.CommandStatusRunning, nil), true, true},
		{"fail running", TransitionFail, cmd(commanddom.CommandStatusRunning, nil), true, true},
		{"fail completed", TransitionFail, cmd(commanddom.CommandStatusCompleted, nil), true, false},
		{"claim canceled", TransitionClaim, cmd(commanddom.CommandStatusCanceled, nil), true, false},
	} {
		if got := transitionAllowed(tc.t, tc.c, tc.mine); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	if s := stateOf(cmd(commanddom.CommandStatusPending, &past)); s != "expired" {
		t.Errorf("stateOf expired pending = %q", s)
	}
}
