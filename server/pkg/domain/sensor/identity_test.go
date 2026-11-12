package sensor

import (
	"strings"
	"testing"
	"time"
)

// observeSeq feeds heartbeats (instance ids, one every interval) through
// Observe the way the service does: an unchanged instance writes nothing.
func observeSeq(t *testing.T, ids []string, interval time.Duration) (InstanceState, []InstanceVerdict) {
	t.Helper()
	var st InstanceState
	var verdicts []InstanceVerdict
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	lastSeen := time.Time{}
	for _, id := range ids {
		if id == st.Current {
			verdicts = append(verdicts, InstanceVerdict{})
		} else {
			var v InstanceVerdict
			st, v = st.Observe(id, now, lastSeen)
			verdicts = append(verdicts, v)
		}
		lastSeen = now
		now = now.Add(interval)
	}
	return st, verdicts
}

func anyCloned(vs []InstanceVerdict) bool {
	for _, v := range vs {
		if v.Cloned {
			return true
		}
	}
	return false
}

func TestObserve_SteadySingleInstance_NotCloned(t *testing.T) {
	_, vs := observeSeq(t, []string{"a", "a", "a", "a", "a"}, 30*time.Second)
	if anyCloned(vs) {
		t.Fatal("one instance must never be flagged")
	}
	if !vs[0].Changed {
		t.Fatal("the first heartbeat sets the current instance")
	}
}

func TestObserve_Restart_NotCloned(t *testing.T) {
	_, vs := observeSeq(t, []string{"a", "a", "b", "b", "b"}, 30*time.Second)
	if anyCloned(vs) {
		t.Fatal("a restart (a replaced by b) is not a clone")
	}
	if !vs[2].Changed || vs[2].Returned {
		t.Fatalf("restart verdict = %+v, want changed and not returned", vs[2])
	}
}

func TestObserve_RestartWithStragglerHeartbeat_NotCloned(t *testing.T) {
	// The old process's last heartbeat lands after the new one's first.
	_, vs := observeSeq(t, []string{"a", "b", "a", "b", "b", "b"}, 5*time.Second)
	if anyCloned(vs) {
		t.Fatal("one straggler heartbeat from the old process must not flag a clone")
	}
}

func TestObserve_CrashLoop_NotCloned(t *testing.T) {
	_, vs := observeSeq(t, []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}, 10*time.Second)
	if anyCloned(vs) {
		t.Fatal("a crash loop (a new instance each time, none comes back) is not a clone")
	}
}

func TestObserve_TwoCopiesAlternating_Cloned(t *testing.T) {
	_, vs := observeSeq(t, []string{"a", "b", "a", "b", "a", "b"}, 15*time.Second)
	if !anyCloned(vs) {
		t.Fatal("two instances alternating must be flagged")
	}
	if !vs[4].Cloned {
		t.Fatalf("expected the flag at the third return, verdicts=%+v", vs)
	}
	if got := strings.Join(vs[4].Live, ","); got != "a,b" {
		t.Fatalf("live = %q, want a,b", got)
	}
}

func TestObserve_ThreeCopiesRoundRobin_Cloned(t *testing.T) {
	_, vs := observeSeq(t, []string{"a", "b", "c", "a", "b", "c"}, 10*time.Second)
	if !anyCloned(vs) {
		t.Fatal("three instances in turn must be flagged")
	}
}

func TestObserve_SlowAlternationOutsideWindow_NotCloned(t *testing.T) {
	// Alternating once per hour is not two live copies.
	_, vs := observeSeq(t, []string{"a", "b", "a", "b", "a"}, time.Hour)
	if anyCloned(vs) {
		t.Fatal("instances alternating outside the window must not be flagged")
	}
}

func TestObserve_StateIsBounded(t *testing.T) {
	ids := make([]string, 0, 40)
	for i := range 40 {
		ids = append(ids, string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	st, _ := observeSeq(t, ids, time.Second)
	if len(st.Seen) > maxTrackedInstances {
		t.Fatalf("seen holds %d instances, want at most %d", len(st.Seen), maxTrackedInstances)
	}
}

func TestObserve_DoesNotMutateReceiver(t *testing.T) {
	now := time.Now()
	st := InstanceState{Current: "a", Seen: map[string]time.Time{"a": now}}
	_, _ = st.Observe("b", now.Add(time.Second), now)
	if _, ok := st.Seen["b"]; ok || st.Current != "a" {
		t.Fatal("Observe must not modify its receiver")
	}
}

func TestSanitizeInstanceID(t *testing.T) {
	cases := map[string]string{
		"":                             "",
		"  ":                           "",
		"0f3c9a1e-7b2d-4c5e-9f00-1a2b": "0f3c9a1e-7b2d-4c5e-9f00-1a2b",
		"abc_DEF.123":                  "abc_DEF.123",
		"has space":                    "",
		"semi;colon":                   "",
		"<script>":                     "",
		strings.Repeat("a", 65):        "",
		strings.Repeat("a", 64):        strings.Repeat("a", 64),
	}
	for in, want := range cases {
		if got := SanitizeInstanceID(in); got != want {
			t.Errorf("SanitizeInstanceID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHeartbeatInstance(t *testing.T) {
	if got := HeartbeatInstance("abc", "host1"); got != "abc" {
		t.Fatalf("an instance id wins, got %q", got)
	}
	h1, h2 := HeartbeatInstance("", "host1"), HeartbeatInstance("", "host2")
	if !strings.HasPrefix(h1, hostInstancePrefix) || h1 == h2 {
		t.Fatalf("hostname-derived instances must be prefixed and distinct: %q %q", h1, h2)
	}
	if strings.Contains(h1, "host1") {
		t.Fatal("the hostname itself is not stored")
	}
	if HeartbeatInstance("", "") != "" || HeartbeatInstance("bad id", "") != "" {
		t.Fatal("no instance id and no hostname: nothing to observe")
	}
}
