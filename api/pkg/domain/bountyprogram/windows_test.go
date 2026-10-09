package bountyprogram

import (
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestTestingWindow_Validate(t *testing.T) {
	ok := TestingWindow{Days: []string{"Mon", "tue"}, Start: "09:00", End: "17:30", Timezone: "Europe/Paris"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []TestingWindow{
		{Start: "09:00", End: "17:00", Timezone: "UTC"},                                        // no day
		{Days: []string{"funday"}, Start: "09:00", End: "17:00", Timezone: "UTC"},              // not a day
		{Days: []string{"mon"}, Start: "17:00", End: "09:00", Timezone: "UTC"},                 // overnight
		{Days: []string{"mon"}, Start: "09:00", End: "09:00", Timezone: "UTC"},                 // empty
		{Days: []string{"mon"}, Start: "9:00", End: "17:00", Timezone: "UTC"},                  // not HH:MM
		{Days: []string{"mon"}, Start: "09:00", End: "24:00", Timezone: "UTC"},                 // no 24:00
		{Days: []string{"mon"}, Start: "09:00", End: "17:00"},                                  // no zone
		{Days: []string{"mon"}, Start: "09:00", End: "17:00", Timezone: "Mars/Olympus"},        // unknown zone
		{Days: []string{"mon"}, Start: "09:00", End: "17:00", Timezone: "../../../etc/passwd"}, // path
		{Days: []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun", "mon"}, Start: "09:00", End: "17:00", Timezone: "UTC"},
	}
	for i, w := range bad {
		if err := w.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("case %d must be refused: %+v (%v)", i, w, err)
		}
	}
}

func TestTestingWindow_Open(t *testing.T) {
	w := TestingWindow{Days: []string{"mon"}, Start: "09:00", End: "17:00", Timezone: "Asia/Ho_Chi_Minh"} // UTC+7
	cases := []struct {
		at   string
		open bool
	}{
		{"2026-10-05T02:00:00Z", true},  // Mon 09:00 local
		{"2026-10-05T01:59:00Z", false}, // Mon 08:59 local
		{"2026-10-05T09:59:00Z", true},  // Mon 16:59 local
		{"2026-10-05T10:00:00Z", false}, // Mon 17:00 local: end is exclusive
		{"2026-10-04T20:00:00Z", false}, // Mon 03:00 local, before start
		{"2026-10-06T03:00:00Z", false}, // Tue local
		{"2026-10-04T23:00:00Z", false}, // Sun 23:00 UTC = Mon 06:00 local
	}
	for _, c := range cases {
		at, _ := time.Parse(time.RFC3339, c.at)
		if got := w.Open(at); got != c.open {
			t.Errorf("%s: open = %v, want %v", c.at, got, c.open)
		}
	}
	if (TestingWindow{Days: []string{"mon"}, Start: "00:00", End: "23:59", Timezone: "bogus"}).Open(time.Now()) {
		t.Error("a window with an unknown zone must never be open")
	}
}

func TestRules_TestingOpen(t *testing.T) {
	monday, _ := time.Parse(time.RFC3339, "2026-10-05T10:00:00Z")
	if !(Rules{}).TestingOpen(monday) {
		t.Fatal("no window means any time")
	}
	r := Rules{TestingWindows: []TestingWindow{
		{Days: []string{"tue"}, Start: "00:00", End: "23:59", Timezone: "UTC"},
		{Days: []string{"mon"}, Start: "08:00", End: "12:00", Timezone: "UTC"},
	}}
	if !r.TestingOpen(monday) {
		t.Fatal("inside the second window")
	}
	if r.TestingOpen(monday.Add(3 * time.Hour)) {
		t.Fatal("outside every window")
	}
}

func TestRules_ValidateWindowsAndRefusedHeaders(t *testing.T) {
	ok := Rules{TestingWindows: []TestingWindow{{Days: []string{"MON"}, Start: "09:00", End: "17:00", Timezone: " UTC "}}}
	n := ok.Normalize()
	if err := n.Validate(); err != nil {
		t.Fatal(err)
	}
	if n.TestingWindows[0].Days[0] != "mon" || n.TestingWindows[0].Timezone != "UTC" {
		t.Fatalf("not normalized: %+v", n.TestingWindows[0])
	}
	many := Rules{}
	for range MaxTestingWindows + 1 {
		many.TestingWindows = append(many.TestingWindows, ok.TestingWindows[0])
	}
	if err := many.Normalize().Validate(); err == nil {
		t.Error("too many windows accepted")
	}
	for _, name := range []string{"Authorization", "cookie", "Host", "Content-Length", "Transfer-Encoding",
		"Connection", "Upgrade", "TE", "Trailer", "Keep-Alive", "Proxy-Authorization", "proxy-connection"} {
		r := Rules{RequiredHeaders: []Header{{Name: name, Value: "x"}}}
		if err := r.Normalize().Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("header %s must be refused (%v)", name, err)
		}
	}
}

func prog(name string, r Rules) *Program { return &Program{Name: name, Rules: r} }

func TestMergeJobRules(t *testing.T) {
	if r, err := MergeJobRules(nil); r != nil || err != nil {
		t.Fatalf("no program: %v %v", r, err)
	}
	a := prog("A", Rules{RateLimitRPS: 10, UserAgent: "jdoe", RequiredHeaders: []Header{{Name: "X-Bug-Bounty", Value: "jdoe"}}})
	b := prog("B", Rules{RateLimitRPS: 3, RequiredHeaders: []Header{{Name: "x-bug-bounty", Value: "jdoe"}, {Name: "X-Other", Value: "1"}}})
	c := prog("C", Rules{})
	r, err := MergeJobRules([]*Program{a, b, c})
	if err != nil {
		t.Fatal(err)
	}
	if r.RateLimit != 3 || r.UserAgent != "jdoe" || len(r.Headers) != 2 || r.Headers["X-Bug-Bounty"] != "jdoe" ||
		r.Headers["X-Other"] != "1" || len(r.Programs) != 3 {
		t.Fatalf("merged %+v", r)
	}
	// A program without a rate does not lift another's cap.
	if r, _ := MergeJobRules([]*Program{c, b}); r.RateLimit != 3 {
		t.Fatalf("rate %d", r.RateLimit)
	}

	conflicts := [][]*Program{
		{a, prog("D", Rules{RequiredHeaders: []Header{{Name: "X-BUG-BOUNTY", Value: "someone-else"}}})},
		{a, prog("E", Rules{UserAgent: "other"})},
	}
	for i, ps := range conflicts {
		if _, err := MergeJobRules(ps); !errors.Is(err, ErrRulesConflict) {
			t.Errorf("case %d: %v, want ErrRulesConflict", i, err)
		}
	}
}
