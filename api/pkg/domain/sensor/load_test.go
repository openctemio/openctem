package sensor

import (
	"math"
	"testing"
	"time"
)

func TestLoadReport_Clamp(t *testing.T) {
	in := LoadReport{
		Resources: &ReportedResources{CPUCores: math.Inf(1), CPUUsedPct: 250, MemTotalBytes: 100,
			MemAvailableBytes: 500, Load1: math.NaN(), DiskFreeBytes: -1},
		Capacity: &ReportedCapacity{SlotsTotal: 500, SlotsFree: 900, ActiveJobs: -3, PerTool: map[string]ToolCost{
			"nuclei":        {EstCPUSeconds: -1, EstMemBytes: 1 << 62, ThroughputTargetsPerMin: math.Inf(1)},
			"../etc/passwd": {EstCPUSeconds: 1},
			"":              {EstCPUSeconds: 1},
		}},
		Queue: &ReportedQueue{Claimed: -1, Running: 1 << 30, OldestAgeSeconds: 1 << 40},
	}
	got := in.Clamp()
	r := got.Resources
	if r.CPUCores != 0 || r.CPUUsedPct != 100 || r.MemAvailableBytes != 100 || r.Load1 != 0 || r.DiskFreeBytes != 0 {
		t.Errorf("resources = %+v", r)
	}
	c := got.Capacity
	if c.SlotsTotal != MaxReportedJobs || c.SlotsFree != MaxReportedJobs || c.ActiveJobs != 0 {
		t.Errorf("capacity slots = %+v", c)
	}
	if len(c.PerTool) != 1 {
		t.Fatalf("per_tool kept %v, want only nuclei", c.PerTool)
	}
	n := c.PerTool["nuclei"]
	if n.EstCPUSeconds != 0 || n.EstMemBytes != MaxReportedBytes || n.ThroughputTargetsPerMin != 0 {
		t.Errorf("nuclei cost = %+v", n)
	}
	q := got.Queue
	if q.Claimed != 0 || q.Running != MaxReportedQueueItems || q.OldestAgeSeconds != MaxReportedQueueAgeSecs {
		t.Errorf("queue = %+v", q)
	}
	// Absent parts stay absent.
	if out := (LoadReport{Queue: &ReportedQueue{}}).Clamp(); out.Resources != nil || out.Capacity != nil || out.Queue == nil {
		t.Errorf("absent parts not kept absent: %+v", out)
	}
}

func TestLoadReport_PerToolBounded(t *testing.T) {
	per := map[string]ToolCost{}
	for i := range 200 {
		per["tool-"+string(rune('a'+i%26))+string(rune('a'+i/26))] = ToolCost{}
	}
	got := LoadReport{Capacity: &ReportedCapacity{PerTool: per}}.Clamp()
	if len(got.Capacity.PerTool) != MaxReportedPerTool {
		t.Fatalf("per_tool = %d entries, want %d", len(got.Capacity.PerTool), MaxReportedPerTool)
	}
}

func TestSensor_FreeSlots(t *testing.T) {
	now := time.Now()
	fresh := now.Add(-time.Minute)
	stale := now.Add(-10 * time.Minute)
	cap3free1 := &ReportedCapacity{SlotsTotal: 3, SlotsFree: 1}
	for name, tc := range map[string]struct {
		maxJobs, current int
		load             LoadReport
		want             int
	}{
		"no report":                 {maxJobs: 5, current: 2, want: 3},
		"held more than capacity":   {maxJobs: 2, current: 4, want: 0},
		"fresh report narrows":      {maxJobs: 5, current: 0, load: LoadReport{Capacity: cap3free1, ReportedAt: &fresh}, want: 1},
		"fresh report cannot widen": {maxJobs: 2, current: 1, load: LoadReport{Capacity: &ReportedCapacity{SlotsTotal: 50, SlotsFree: 50}, ReportedAt: &fresh}, want: 1},
		// A stale report's free slots are ignored; its slots still bound the
		// capacity (effective max jobs, RFC-033), like the generated column.
		"stale report: free slots ignored": {maxJobs: 5, current: 0, load: LoadReport{Capacity: cap3free1, ReportedAt: &stale}, want: 3},
		"slots_total 0 is no report":       {maxJobs: 5, current: 0, load: LoadReport{Capacity: &ReportedCapacity{}, ReportedAt: &fresh}, want: 5},
		"no capacity limit":                {maxJobs: 0, current: 9, want: 1},
	} {
		a := &Sensor{MaxConcurrentJobs: tc.maxJobs, CurrentJobs: tc.current, Load: tc.load}
		if got := a.FreeSlots(now); got != tc.want {
			t.Errorf("%s: FreeSlots = %d, want %d", name, got, tc.want)
		}
	}
}

func TestReportedResources_Percents(t *testing.T) {
	cpu, mem, ok := (&ReportedResources{CPUUsedPct: 40, MemTotalBytes: 1000, MemAvailableBytes: 250}).ResourcePercents()
	if !ok || cpu != 40 || mem != 75 {
		t.Fatalf("got %v %v %v", cpu, mem, ok)
	}
	if _, _, ok := (*ReportedResources)(nil).ResourcePercents(); ok {
		t.Fatal("nil resources reported ok")
	}
}
