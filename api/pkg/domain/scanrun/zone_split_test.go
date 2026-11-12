package scanrun

import "testing"

func TestSplitOutcome(t *testing.T) {
	cases := []struct {
		name string
		in   []RunStatus
		want RunStatus
		ok   bool
	}{
		{"none", nil, "", false},
		{"one open", []RunStatus{RunStatusCompleted, RunStatusRunning}, "", false},
		{"all completed", []RunStatus{RunStatusCompleted, RunStatusCompleted}, RunStatusCompleted, true},
		{"all canceled", []RunStatus{RunStatusCanceled, RunStatusCanceled}, RunStatusCanceled, true},
		{"no results", []RunStatus{RunStatusFailed, RunStatusTimeout, RunStatusCanceled}, RunStatusFailed, true},
		{"some results", []RunStatus{RunStatusCompleted, RunStatusFailed}, RunStatusPartial, true},
		{"partial child", []RunStatus{RunStatusPartial, RunStatusCompleted}, RunStatusPartial, true},
	}
	for _, c := range cases {
		got, ok := SplitOutcome(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: SplitOutcome = %s %v, want %s %v", c.name, got, ok, c.want, c.ok)
		}
	}
}
