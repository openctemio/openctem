package sensor

// Sensor load report (docs/rfcs/RFC-030-scan-work-distribution.md §5.8). On
// each heartbeat the SDK reports what it measures about the machine it runs
// on (cgroup-aware CPU and memory, load average, free disk), the job slots it
// computes from that (dynamic, never above its configured cap), what each
// tool has cost it per target, and its local work queue.
//
// The report is untrusted: every value is clamped here before it is stored,
// and it can only LOWER what dispatch hands the sensor. The server's own
// count of the commands a sensor holds (acknowledged or running) is the
// truth for capacity (RFC-030 D5); a fresh report narrows it further.

import (
	"math"
	"regexp"
	"strings"
	"time"
)

// Bounds on a load report. Anything beyond them is clamped or dropped.
const (
	// LoadReportFreshness is how long a load report counts for dispatch.
	// Three heartbeat intervals: an older report says nothing about now.
	LoadReportFreshness = 3 * time.Minute

	MaxReportedCPUCores      = 4096
	MaxReportedBytes         = int64(1) << 50 // 1 PiB
	MaxReportedLoad          = 100000
	MaxReportedPerTool       = 64
	MaxReportedToolCPUSecs   = 7 * 24 * 3600 // a week of CPU per target
	MaxReportedThroughput    = 1_000_000     // targets per minute
	MaxReportedQueueItems    = 100000
	MaxReportedQueueAgeSecs  = 30 * 24 * 3600
	MaxReportedActiveCommand = 1000
)

// ReportedResources is the machine the sensor runs on, as the SDK measured
// it (container limits, not the host, when it runs in one).
type ReportedResources struct {
	CPUCores          float64 `json:"cpu_cores"`
	CPUUsedPct        float64 `json:"cpu_used_pct"`
	MemTotalBytes     int64   `json:"mem_total_bytes"`
	MemAvailableBytes int64   `json:"mem_available_bytes"`
	Load1             float64 `json:"load1"`
	DiskFreeBytes     int64   `json:"disk_free_bytes"`
}

// ToolCost is what one tool has cost the sensor per target, learned by the
// SDK from completed jobs.
type ToolCost struct {
	EstCPUSeconds           float64 `json:"est_cpu_s"`
	EstMemBytes             int64   `json:"est_mem_bytes"`
	ThroughputTargetsPerMin float64 `json:"throughput_targets_per_min"`
}

// ReportedCapacity is the sensor's own view of its job slots.
type ReportedCapacity struct {
	SlotsTotal int                 `json:"slots_total"`
	SlotsFree  int                 `json:"slots_free"`
	ActiveJobs int                 `json:"active_jobs"`
	PerTool    map[string]ToolCost `json:"per_tool,omitempty"`
}

// ReportedQueue is the sensor's local work queue (the SDK's; the platform
// queue is authoritative).
type ReportedQueue struct {
	Claimed          int   `json:"claimed"`
	Running          int   `json:"running"`
	QueuedLocal      int   `json:"queued_local"`
	OldestAgeSeconds int64 `json:"oldest_age_seconds"`
}

// LoadReport is the load a heartbeat carried, or the one last stored. A nil
// part was not reported.
type LoadReport struct {
	Resources *ReportedResources `json:"resources,omitempty"`
	Capacity  *ReportedCapacity  `json:"capacity,omitempty"`
	Queue     *ReportedQueue     `json:"queue,omitempty"`
	// ReportedAt is when the stored report was written; nil before the first.
	ReportedAt *time.Time `json:"reported_at,omitempty"`
}

// IsEmpty reports whether nothing was reported.
func (l *LoadReport) IsEmpty() bool {
	return l == nil || (l.Resources == nil && l.Capacity == nil && l.Queue == nil)
}

// Clamp returns the report with every value bounded and every tool name
// that is not a plausible tool name dropped. It never returns parts that
// were not reported.
func (l LoadReport) Clamp() LoadReport {
	out := LoadReport{ReportedAt: l.ReportedAt}
	if l.Resources != nil {
		r := *l.Resources
		r.CPUCores = clampFloat(r.CPUCores, MaxReportedCPUCores)
		r.CPUUsedPct = clampFloat(r.CPUUsedPct, 100)
		r.MemTotalBytes = clampInt64(r.MemTotalBytes, MaxReportedBytes)
		r.MemAvailableBytes = clampInt64(r.MemAvailableBytes, MaxReportedBytes)
		if r.MemTotalBytes > 0 && r.MemAvailableBytes > r.MemTotalBytes {
			r.MemAvailableBytes = r.MemTotalBytes
		}
		r.Load1 = clampFloat(r.Load1, MaxReportedLoad)
		r.DiskFreeBytes = clampInt64(r.DiskFreeBytes, MaxReportedBytes)
		out.Resources = &r
	}
	if l.Capacity != nil {
		c := ReportedCapacity{
			SlotsTotal: clampInt(l.Capacity.SlotsTotal, MaxReportedJobs),
			SlotsFree:  clampInt(l.Capacity.SlotsFree, MaxReportedJobs),
			ActiveJobs: clampInt(l.Capacity.ActiveJobs, MaxReportedActiveCommand),
		}
		if c.SlotsTotal > 0 && c.SlotsFree > c.SlotsTotal {
			c.SlotsFree = c.SlotsTotal
		}
		for name, cost := range l.Capacity.PerTool {
			if len(c.PerTool) >= MaxReportedPerTool {
				break
			}
			name = strings.TrimSpace(name)
			if !reportedToolName.MatchString(name) {
				continue
			}
			if c.PerTool == nil {
				c.PerTool = make(map[string]ToolCost)
			}
			c.PerTool[name] = ToolCost{
				EstCPUSeconds:           clampFloat(cost.EstCPUSeconds, MaxReportedToolCPUSecs),
				EstMemBytes:             clampInt64(cost.EstMemBytes, MaxReportedBytes),
				ThroughputTargetsPerMin: clampFloat(cost.ThroughputTargetsPerMin, MaxReportedThroughput),
			}
		}
		out.Capacity = &c
	}
	if l.Queue != nil {
		out.Queue = &ReportedQueue{
			Claimed:          clampInt(l.Queue.Claimed, MaxReportedQueueItems),
			Running:          clampInt(l.Queue.Running, MaxReportedQueueItems),
			QueuedLocal:      clampInt(l.Queue.QueuedLocal, MaxReportedQueueItems),
			OldestAgeSeconds: clampInt64(l.Queue.OldestAgeSeconds, MaxReportedQueueAgeSecs),
		}
	}
	return out
}

// reportedToolName is what a per-tool key may look like: a tool catalog name
// (tools.name is VARCHAR(50)).
var reportedToolName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,49}$`)

// IsFresh reports whether the stored report is recent enough for dispatch.
func (l LoadReport) IsFresh(now time.Time) bool {
	return l.ReportedAt != nil && now.Sub(*l.ReportedAt) <= LoadReportFreshness
}

// FreeSlots is how many more jobs dispatch may hand the sensor now: its
// effective capacity minus the commands it holds (CurrentJobs, counted by
// the server from the commands table), and no more than the free slots a
// fresh load report gives. Never negative. A sensor without a capacity limit
// is treated as having one free slot.
func (a *Sensor) FreeSlots(now time.Time) int {
	limit := a.EffectiveMaxConcurrentJobs()
	if limit <= 0 {
		return 1
	}
	free := limit - a.CurrentJobs
	if a.Load.IsFresh(now) && a.Load.Capacity != nil && a.Load.Capacity.SlotsTotal > 0 {
		free = min(free, a.Load.Capacity.SlotsFree)
	}
	return max(free, 0)
}

// ToolThroughput is the targets per minute a fresh load report gives for
// the tool, 0 when unknown.
func (a *Sensor) ToolThroughput(tool string, now time.Time) float64 {
	if !a.Load.IsFresh(now) || a.Load.Capacity == nil {
		return 0
	}
	return a.Load.Capacity.PerTool[tool].ThroughputTargetsPerMin
}

// ResourcePercents derives the CPU and memory percentages the load score
// uses from a resources report: CPU as reported, memory as the share of the
// limit in use. ok is false when the report has neither.
func (r *ReportedResources) ResourcePercents() (cpu, mem float64, ok bool) {
	if r == nil {
		return 0, 0, false
	}
	cpu = r.CPUUsedPct
	if r.MemTotalBytes > 0 {
		mem = 100 * float64(r.MemTotalBytes-r.MemAvailableBytes) / float64(r.MemTotalBytes)
	}
	return cpu, mem, r.CPUUsedPct > 0 || r.MemTotalBytes > 0
}

func clampFloat(v, hi float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0
	}
	return math.Min(v, hi)
}

func clampInt(v, hi int) int {
	if v < 0 {
		return 0
	}
	return min(v, hi)
}
