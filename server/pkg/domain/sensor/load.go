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
	"slices"
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
	MaxReportedLevelSecs     = 30 * 24 * 3600
	MaxReportedCounter       = 1 << 30
	MaxReportedReasons       = 6
)

// Host pressure levels a sensor reports (research/318). An empty level is
// unknown and counts as ok.
const (
	PressureOK         = "ok"
	PressureElevated   = "elevated"
	PressureOverloaded = "overloaded"
)

// pressureReasons is the closed set of reason tokens; others are dropped.
var pressureReasons = map[string]bool{
	"cpu": true, "memory": true, "io": true, "load": true, "mem_available": true, "fds": true,
}

// ReportedResources is the machine the sensor runs on, as the SDK measured
// it (container limits, not the host, when it runs in one).
type ReportedResources struct {
	CPUCores          float64 `json:"cpu_cores"`
	CPUUsedPct        float64 `json:"cpu_used_pct"`
	MemTotalBytes     int64   `json:"mem_total_bytes"`
	MemAvailableBytes int64   `json:"mem_available_bytes"`
	Load1             float64 `json:"load1"`
	DiskFreeBytes     int64   `json:"disk_free_bytes"`
	// Pressure is the stall and contention the host shows; nil from a
	// sensor that does not measure it.
	Pressure *ReportedPressure `json:"pressure,omitempty"`
}

// ReportedPressure is how loaded the sensor's host is: kernel stall
// averages (percent of time some or all tasks waited), load per CPU and
// descriptor use, and how much CPU other programs on the host take.
type ReportedPressure struct {
	Level        string   `json:"level"`
	Reasons      []string `json:"reasons,omitempty"`
	LevelSeconds int64    `json:"level_seconds"`
	PSI          bool     `json:"psi"`
	CPUSomeAvg10 float64  `json:"cpu_some_avg10"`
	MemSomeAvg10 float64  `json:"mem_some_avg10"`
	MemFullAvg10 float64  `json:"mem_full_avg10"`
	IOSomeAvg10  float64  `json:"io_some_avg10"`
	IOFullAvg10  float64  `json:"io_full_avg10"`
	LoadPerCPU   float64  `json:"load_per_cpu"`
	FDUsedPct    float64  `json:"fd_used_pct"`
	HostCPUBusy  float64  `json:"host_cpu_busy_pct"`
	ForeignCPU   float64  `json:"foreign_cpu_pct"`
	CPUThrottled float64  `json:"cpu_throttled_pct"`
	Noisy        bool     `json:"noisy_neighbor"`
}

// ReportedTransient counts the transient start problems the sensor met and
// absorbed since it started.
type ReportedTransient struct {
	HandshakeTimeouts int `json:"handshake_timeouts"`
	SlowStarts        int `json:"slow_starts"`
	OOMKills          int `json:"oom_kills"`
	StartEAGAIN       int `json:"start_eagain"`
	Retried           int `json:"retried"`
	Recovered         int `json:"recovered"`
}

func (p ReportedPressure) clamp() *ReportedPressure {
	switch p.Level {
	case PressureOK, PressureElevated, PressureOverloaded:
	default:
		p.Level = ""
	}
	p.LevelSeconds = clampInt64(p.LevelSeconds, MaxReportedLevelSecs)
	for _, f := range []*float64{&p.CPUSomeAvg10, &p.MemSomeAvg10, &p.MemFullAvg10, &p.IOSomeAvg10,
		&p.IOFullAvg10, &p.FDUsedPct, &p.CPUThrottled, &p.HostCPUBusy, &p.ForeignCPU} {
		*f = clampFloat(*f, 100)
	}
	p.LoadPerCPU = clampFloat(p.LoadPerCPU, MaxReportedLoad)
	var reasons []string
	for _, r := range p.Reasons {
		if len(reasons) >= MaxReportedReasons {
			break
		}
		if pressureReasons[r] && !slices.Contains(reasons, r) {
			reasons = append(reasons, r)
		}
	}
	p.Reasons = reasons
	return &p
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
	// LaunchesHeld is the tool starts the sensor holds back for now and
	// ToolsRunning the tool processes it runs; Transient counts the start
	// problems it absorbed.
	LaunchesHeld int                `json:"launches_held,omitempty"`
	ToolsRunning int                `json:"tools_running,omitempty"`
	Transient    *ReportedTransient `json:"transient,omitempty"`
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

// SlotsTotal is the job slots the report gives (what the sensor can run
// now), 0 when it gives none.
func (l *LoadReport) SlotsTotal() int {
	if l == nil || l.Capacity == nil {
		return 0
	}
	return max(l.Capacity.SlotsTotal, 0)
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
		if r.Pressure != nil {
			r.Pressure = r.Pressure.clamp()
		}
		out.Resources = &r
	}
	if l.Capacity != nil {
		c := ReportedCapacity{
			SlotsTotal: clampInt(l.Capacity.SlotsTotal, MaxReportedJobs),
			SlotsFree:  clampInt(l.Capacity.SlotsFree, MaxReportedJobs),
			ActiveJobs: clampInt(l.Capacity.ActiveJobs, MaxReportedActiveCommand),
		}
		c.LaunchesHeld = clampInt(l.Capacity.LaunchesHeld, MaxReportedCounter)
		c.ToolsRunning = clampInt(l.Capacity.ToolsRunning, MaxReportedCounter)
		if t := l.Capacity.Transient; t != nil {
			c.Transient = &ReportedTransient{
				HandshakeTimeouts: clampInt(t.HandshakeTimeouts, MaxReportedCounter),
				SlowStarts:        clampInt(t.SlowStarts, MaxReportedCounter),
				OOMKills:          clampInt(t.OOMKills, MaxReportedCounter),
				StartEAGAIN:       clampInt(t.StartEAGAIN, MaxReportedCounter),
				Retried:           clampInt(t.Retried, MaxReportedCounter),
				Recovered:         clampInt(t.Recovered, MaxReportedCounter),
			}
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
	return a.freeSlots(now, true)
}

// PressureLevel is the host pressure level of a FRESH load report
// (PressureOK, PressureElevated, PressureOverloaded), "" when there is no
// fresh report or it gives none.
func (a *Sensor) PressureLevel(now time.Time) string {
	if !a.Load.IsFresh(now) || a.Load.Resources == nil || a.Load.Resources.Pressure == nil {
		return ""
	}
	return a.Load.Resources.Pressure.Level
}

// PressureNarrowed reports whether host pressure alone lowers the free
// slots now (the placement reason sensor_overloaded).
func (a *Sensor) PressureNarrowed(now time.Time) bool {
	return a.freeSlots(now, true) < a.freeSlots(now, false)
}

// freeSlots is FreeSlots with host pressure applied or not. Pressure rule
// (mirrored by the free-slots SQL): overloaded gives no slot to a sensor
// that holds a command and at most one to an idle one; elevated gives at
// most one.
func (a *Sensor) freeSlots(now time.Time, pressure bool) int {
	limit := a.EffectiveMaxConcurrentJobs()
	if limit <= 0 {
		return 1
	}
	free := limit - a.CurrentJobs
	if a.Load.IsFresh(now) && a.Load.Capacity != nil && a.Load.Capacity.SlotsTotal > 0 {
		free = min(free, a.Load.Capacity.SlotsFree)
	}
	if pressure {
		switch a.PressureLevel(now) {
		case PressureOverloaded:
			if a.CurrentJobs >= 1 {
				free = 0
			} else {
				free = min(free, 1)
			}
		case PressureElevated:
			free = min(free, 1)
		}
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
