package compliancecheck

import (
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestResultOf(t *testing.T) {
	cases := []struct {
		kind, outcome, native string
		want                  Result
		ok                    bool
	}{
		{"pass", "", "PASSED", ResultPass, true},
		{"FAIL", "", "", ResultFail, true},
		{"review", "", "WARNING", ResultManual, true},
		{"not_applicable", "", "", ResultNotApplicable, true},
		{"not_applicable", "error", "", ResultError, true},
		{"not_applicable", "skipped", "", ResultNotApplicable, true},
		// An importer without the outcome: the scanner's own word keeps the error.
		{"not_applicable", "", "ERROR", ResultError, true},
		{"not_applicable", "", "SKIPPED", ResultNotApplicable, true},
		// The outcome wins over the native word.
		{"not_applicable", "skipped", "ERROR", ResultNotApplicable, true},
		{"open", "", "", "", false},
		{"", "", "", "", false},
	}
	for _, c := range cases {
		got, ok := ResultOf(c.kind, c.outcome, c.native)
		if got != c.want || ok != c.ok {
			t.Errorf("ResultOf(%q, %q, %q) = %q, %v; want %q, %v", c.kind, c.outcome, c.native, got, ok, c.want, c.ok)
		}
	}
}

func TestResultOpensFinding(t *testing.T) {
	for _, r := range Results() {
		want := r == ResultFail || r == ResultManual
		if r.OpensFinding() != want {
			t.Errorf("%s.OpensFinding() = %v", r, !want)
		}
	}
}

func TestBenchmarkKey(t *testing.T) {
	cases := map[string]string{
		"CIS Microsoft Windows Server 2022 Benchmark": "cis-microsoft-windows-server-2022-benchmark",
		"  CIS Ubuntu Linux 22.04 LTS ":               "cis-ubuntu-linux-22.04-lts",
		"DISA STIG: RHEL/8":                           "disa-stig-rhel-8",
		"":                                            "",
		"---":                                         "",
	}
	for in, want := range cases {
		if got := BenchmarkKey(in); got != want {
			t.Errorf("BenchmarkKey(%q) = %q, want %q", in, got, want)
		}
	}
	long := BenchmarkKey(strings.Repeat("a b ", 200))
	if len(long) > MaxBenchmarkKeyLen || strings.HasSuffix(long, "-") {
		t.Errorf("long key %q not bounded", long)
	}
	if strings.ContainsAny(BenchmarkKey("a:b/c"), ":/") {
		t.Error("key keeps a separator")
	}
}

func TestEvidenceHash(t *testing.T) {
	if (Evidence{}).Hash() != "" {
		t.Fatal("empty evidence has a hash")
	}
	a := Evidence{Actual: "0", Expected: "1"}
	b := Evidence{Actual: " 0 ", Expected: "1"}
	if a.Hash() != b.Hash() {
		t.Fatal("trimmed values hash differently")
	}
	if a.Hash() == (Evidence{Actual: "1", Expected: "1"}).Hash() {
		t.Fatal("different evidence, same hash")
	}
	big := Evidence{Actual: strings.Repeat("é", MaxEvidenceValueLen+10)}.Bounded()
	if n := len([]rune(big.Actual)); n != MaxEvidenceValueLen {
		t.Fatalf("bounded actual has %d characters", n)
	}
}

func TestObservationValid(t *testing.T) {
	o := Observation{AssetID: shared.NewID(), BenchmarkKey: "cis-x", ControlID: "1.1", Result: ResultPass, ObservedAt: time.Now()}
	if !o.Valid() {
		t.Fatal("complete observation invalid")
	}
	for name, mut := range map[string]func(*Observation){
		"asset":   func(o *Observation) { o.AssetID = shared.ID{} },
		"bench":   func(o *Observation) { o.BenchmarkKey = "" },
		"control": func(o *Observation) { o.ControlID = " " },
		"result":  func(o *Observation) { o.Result = "unknown" },
		"time":    func(o *Observation) { o.ObservedAt = time.Time{} },
	} {
		c := o
		mut(&c)
		if c.Valid() {
			t.Errorf("observation without %s is valid", name)
		}
	}
}
