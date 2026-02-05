// Package agent defines the Agent domain entity for scanner/collector/agent management.
package agent

import (
	"net"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// AgentType represents the type of agent.
// The platform supports 4 main component types:
//   - runner: CI/CD one-shot scans (execution_mode: standalone)
//   - worker: Server-controlled daemon (execution_mode: daemon)
//   - collector: Data collection agent (execution_mode: daemon)
//   - sensor: External Attack Surface Monitoring (EASM)
type AgentType string

const (
	// Primary types
	AgentTypeRunner    AgentType = "runner"    // CI/CD one-shot scans
	AgentTypeWorker    AgentType = "worker"    // Server-controlled daemon
	AgentTypeCollector AgentType = "collector" // Data collection agent
	AgentTypeSensor    AgentType = "sensor"    // EASM sensor
)

// IsValid checks if the agent type is valid.
func (t AgentType) IsValid() bool {
	switch t {
	case AgentTypeRunner, AgentTypeWorker, AgentTypeCollector, AgentTypeSensor:
		return true
	}
	return false
}

// IsRunner checks if this is a runner type (one-shot CI/CD).
func (t AgentType) IsRunner() bool {
	return t == AgentTypeRunner
}

// IsWorker checks if this is a worker type (server-controlled daemon).
func (t AgentType) IsWorker() bool {
	return t == AgentTypeWorker
}

// IsCollector checks if this is a collector type.
func (t AgentType) IsCollector() bool {
	return t == AgentTypeCollector
}

// IsSensor checks if this is a sensor type.
func (t AgentType) IsSensor() bool {
	return t == AgentTypeSensor
}

// DefaultExecutionMode returns the default execution mode for this agent type.
func (t AgentType) DefaultExecutionMode() ExecutionMode {
	switch t {
	case AgentTypeRunner:
		return ExecutionModeStandalone
	case AgentTypeWorker, AgentTypeCollector, AgentTypeSensor:
		return ExecutionModeDaemon
	default:
		return ExecutionModeStandalone
	}
}

// AgentStatus represents the ADMIN-CONTROLLED status of an agent.
// This determines whether the agent is ALLOWED to authenticate.
type AgentStatus string

const (
	AgentStatusActive   AgentStatus = "active"   // Agent is enabled (can authenticate)
	AgentStatusDisabled AgentStatus = "disabled" // Admin disabled (cannot authenticate)
	AgentStatusRevoked  AgentStatus = "revoked"  // Access permanently revoked
)

// IsValid checks if the agent status is valid.
func (s AgentStatus) IsValid() bool {
	switch s {
	case AgentStatusActive, AgentStatusDisabled, AgentStatusRevoked:
		return true
	}
	return false
}

// CanAuthenticate checks if the status allows authentication.
func (s AgentStatus) CanAuthenticate() bool {
	return s == AgentStatusActive
}

// AgentHealth represents the AUTOMATIC health state based on heartbeat.
// This is for monitoring only, does NOT affect authentication.
type AgentHealth string

const (
	AgentHealthUnknown AgentHealth = "unknown" // Never seen (just registered)
	AgentHealthOnline  AgentHealth = "online"  // Recently sent heartbeat
	AgentHealthOffline AgentHealth = "offline" // No recent heartbeat
	AgentHealthError   AgentHealth = "error"   // Last operation had errors
)

// IsValid checks if the agent health is valid.
func (h AgentHealth) IsValid() bool {
	switch h {
	case AgentHealthUnknown, AgentHealthOnline, AgentHealthOffline, AgentHealthError:
		return true
	}
	return false
}

// ExecutionMode represents how the agent executes tasks.
type ExecutionMode string

const (
	ExecutionModeStandalone ExecutionMode = "standalone" // Triggered externally (CI/CD, cron, webhook)
	ExecutionModeDaemon     ExecutionMode = "daemon"     // Long-running, polls for commands
)

// IsValid checks if the execution mode is valid.
func (m ExecutionMode) IsValid() bool {
	switch m {
	case ExecutionModeStandalone, ExecutionModeDaemon:
		return true
	}
	return false
}

// Capability represents an agent's capability.
type Capability string

const (
	CapabilitySAST      Capability = "sast"      // Static Application Security Testing
	CapabilitySCA       Capability = "sca"       // Software Composition Analysis
	CapabilitySecrets   Capability = "secrets"   // Secret Detection
	CapabilityIAC       Capability = "iac"       // Infrastructure as Code
	CapabilityDAST      Capability = "dast"      // Dynamic Application Security Testing
	CapabilityInfra     Capability = "infra"     // Infrastructure Scanning
	CapabilityContainer Capability = "container" // Container Scanning
	CapabilityWeb3      Capability = "web3"      // Web3/Blockchain Security
	CapabilityCollector Capability = "collector" // Data Collection
	CapabilityAPI       Capability = "api"       // API Security Testing
)

// Agent represents a registered agent (runner, worker, collector, or sensor).
type Agent struct {
	ID            shared.ID
	TenantID      *shared.ID // nil for platform agents (is_platform_agent = true)
	Name          string
	Type          AgentType
	Description   string
	Capabilities  []string
	Tools         []string // Specific tools: semgrep, trivy, nuclei, nmap, etc.
	ExecutionMode ExecutionMode
	Status        AgentStatus // Admin-controlled: active, disabled, revoked
	Health        AgentHealth // Automatic heartbeat: unknown, online, offline, error
	StatusMessage string

	// Platform agent flag (SaaS model)
	// Platform agents are managed by Exploop and don't count towards tenant's agent limit.
	// Tenants can use platform agents for their scans without provisioning their own.
	IsPlatformAgent bool


	// API key for authentication
	APIKeyHash   string
	APIKeyPrefix string

	// Metadata and configuration
	Labels   map[string]interface{}
	Config   map[string]interface{}
	Metadata map[string]interface{}

	// Runtime info
	Version   string
	Hostname  string
	IPAddress net.IP

	// System metrics (from heartbeat)
	CPUPercent        float64
	MemoryPercent     float64
	DiskReadMBPS      float64 // Disk read throughput in MB/s
	DiskWriteMBPS     float64 // Disk write throughput in MB/s
	NetworkRxMBPS     float64 // Network receive throughput in MB/s
	NetworkTxMBPS     float64 // Network transmit throughput in MB/s
	LoadScore         float64 // Computed weighted load score (lower is better)
	MetricsUpdatedAt  *time.Time
	ActiveJobs        int
	CurrentJobs       int
	MaxConcurrentJobs int
	Region            string

	// Statistics
	LastSeenAt    *time.Time // Last heartbeat timestamp - effectively "last online time"
	LastOfflineAt *time.Time // When agent went offline (heartbeat timeout)
	LastErrorAt   *time.Time
	TotalFindings int64
	TotalScans    int64
	ErrorCount    int64

	// Timestamps
	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewAgent creates a new tenant-owned Agent entity.
func NewAgent(
	tenantID shared.ID,
	name string,
	agentType AgentType,
	description string,
	capabilities []string,
	tools []string,
	executionMode ExecutionMode,
) (*Agent, error) {
	if name == "" {
		return nil, shared.NewDomainError("VALIDATION", "name is required", shared.ErrValidation)
	}

	if !agentType.IsValid() {
		return nil, shared.NewDomainError("VALIDATION", "invalid agent type", shared.ErrValidation)
	}

	if !executionMode.IsValid() {
		executionMode = ExecutionModeStandalone
	}

	now := time.Now()
	return &Agent{
		ID:              shared.NewID(),
		TenantID:        &tenantID, // Tenant agent - has owner
		Name:            name,
		Type:            agentType,
		Description:     description,
		Capabilities:    capabilities,
		Tools:           tools,
		ExecutionMode:   executionMode,
		Status:          AgentStatusActive,  // Admin-controlled: enabled by default
		Health:          AgentHealthUnknown, // Automatic: unknown until first heartbeat
		IsPlatformAgent: false,              // Tenant agent
		Labels:          make(map[string]interface{}),
		Config:          make(map[string]interface{}),
		Metadata:        make(map[string]interface{}),
		CreatedAt:       now,
		UpdatedAt:       now,
	}, nil
}


// SetAPIKey sets the hashed API key and prefix.
func (a *Agent) SetAPIKey(hash, prefix string) {
	a.APIKeyHash = hash
	a.APIKeyPrefix = prefix
	a.UpdatedAt = time.Now()
}

// UpdateLastSeen updates the last seen timestamp and sets health to online.
func (a *Agent) UpdateLastSeen() {
	now := time.Now()
	a.LastSeenAt = &now
	a.UpdatedAt = now
	a.Health = AgentHealthOnline
}

// RecordError records an error and updates error timestamp.
func (a *Agent) RecordError(message string) {
	now := time.Now()
	a.ErrorCount++
	a.LastErrorAt = &now
	a.StatusMessage = message
	a.UpdatedAt = now
}

// IncrementFindings increments the total findings counter.
func (a *Agent) IncrementFindings(count int64) {
	a.TotalFindings += count
	a.UpdatedAt = time.Now()
}

// IncrementScans increments the total scans counter.
func (a *Agent) IncrementScans() {
	a.TotalScans++
	a.UpdatedAt = time.Now()
}

// SetStatus sets the agent status.
func (a *Agent) SetStatus(status AgentStatus, message string) {
	a.Status = status
	a.StatusMessage = message
	a.UpdatedAt = time.Now()
}

// Activate activates the agent.
func (a *Agent) Activate() {
	a.Status = AgentStatusActive
	a.StatusMessage = ""
	a.UpdatedAt = time.Now()
}

// Disable disables the agent (admin action).
func (a *Agent) Disable(reason string) {
	a.Status = AgentStatusDisabled
	a.StatusMessage = reason
	a.UpdatedAt = time.Now()
}

// Revoke revokes the agent access.
func (a *Agent) Revoke(reason string) {
	a.Status = AgentStatusRevoked
	a.StatusMessage = reason
	a.UpdatedAt = time.Now()
}

// UpdateRuntimeInfo updates runtime information from heartbeat.
func (a *Agent) UpdateRuntimeInfo(version, hostname string, ip net.IP) {
	a.Version = version
	a.Hostname = hostname
	a.IPAddress = ip
	a.UpdatedAt = time.Now()
}

// UpdateMetrics updates system metrics from heartbeat.
func (a *Agent) UpdateMetrics(cpuPercent, memoryPercent float64, activeJobs int, region string) {
	a.CPUPercent = cpuPercent
	a.MemoryPercent = memoryPercent
	a.ActiveJobs = activeJobs
	if region != "" {
		a.Region = region
	}
	a.UpdatedAt = time.Now()
}

// ExtendedMetrics represents all system metrics for load balancing.
type ExtendedMetrics struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
	DiskReadMBPS  float64 `json:"disk_read_mbps"`
	DiskWriteMBPS float64 `json:"disk_write_mbps"`
	NetworkRxMBPS float64 `json:"network_rx_mbps"`
	NetworkTxMBPS float64 `json:"network_tx_mbps"`
	ActiveJobs    int     `json:"active_jobs"`
	Region        string  `json:"region,omitempty"`
}

// UpdateExtendedMetrics updates all system metrics from heartbeat including disk I/O and network.
func (a *Agent) UpdateExtendedMetrics(metrics ExtendedMetrics) {
	a.CPUPercent = metrics.CPUPercent
	a.MemoryPercent = metrics.MemoryPercent
	a.DiskReadMBPS = metrics.DiskReadMBPS
	a.DiskWriteMBPS = metrics.DiskWriteMBPS
	a.NetworkRxMBPS = metrics.NetworkRxMBPS
	a.NetworkTxMBPS = metrics.NetworkTxMBPS
	a.ActiveJobs = metrics.ActiveJobs
	if metrics.Region != "" {
		a.Region = metrics.Region
	}
	// Compute load score
	a.LoadScore = a.ComputeLoadScore()
	now := time.Now()
	a.MetricsUpdatedAt = &now
	a.UpdatedAt = now
}

// LoadBalancingWeights defines the weights for load score computation.
// These weights can be configured via environment variables.
type LoadBalancingWeights struct {
	JobLoad float64 // Weight for job load factor (default: 0.30)
	CPU     float64 // Weight for CPU usage (default: 0.40)
	Memory  float64 // Weight for memory usage (default: 0.15)
	DiskIO  float64 // Weight for disk I/O (default: 0.10)
	Network float64 // Weight for network I/O (default: 0.05)
}

// DefaultLoadBalancingWeights returns the default weights for load score computation.
func DefaultLoadBalancingWeights() LoadBalancingWeights {
	return LoadBalancingWeights{
		JobLoad: 0.30,
		CPU:     0.40,
		Memory:  0.15,
		DiskIO:  0.10,
		Network: 0.05,
	}
}

// ComputeLoadScore calculates the weighted load score for agent selection.
// Lower score = better candidate for receiving new jobs.
// Formula: score = (w1 * job_load) + (w2 * cpu) + (w3 * memory) + (w4 * io_score) + (w5 * net_score)
func (a *Agent) ComputeLoadScore() float64 {
	return a.ComputeLoadScoreWithWeights(DefaultLoadBalancingWeights())
}

// ComputeLoadScoreWithWeights calculates load score with custom weights.
func (a *Agent) ComputeLoadScoreWithWeights(weights LoadBalancingWeights) float64 {
	// Calculate job load percentage (0-100)
	var jobLoad float64
	if a.MaxConcurrentJobs > 0 {
		jobLoad = (float64(a.CurrentJobs) / float64(a.MaxConcurrentJobs)) * 100
	}

	// Calculate I/O score (0-100)
	// Assuming max throughput of 500 MB/s combined
	const maxDiskThroughput = 500.0
	ioScore := min(100.0, ((a.DiskReadMBPS+a.DiskWriteMBPS)/maxDiskThroughput)*100)

	// Calculate network score (0-100)
	// Assuming max throughput of 1000 MB/s (1 Gbps) combined
	const maxNetworkThroughput = 1000.0
	netScore := min(100.0, ((a.NetworkRxMBPS+a.NetworkTxMBPS)/maxNetworkThroughput)*100)

	// Weighted score formula
	score := (weights.JobLoad * jobLoad) +
		(weights.CPU * a.CPUPercent) +
		(weights.Memory * a.MemoryPercent) +
		(weights.DiskIO * ioScore) +
		(weights.Network * netScore)

	return score
}

// HasCapability checks if the agent has a specific capability.
func (a *Agent) HasCapability(cap string) bool {
	for _, c := range a.Capabilities {
		if c == cap {
			return true
		}
	}
	return false
}

// HasTool checks if the agent has a specific tool.
func (a *Agent) HasTool(tool string) bool {
	for _, t := range a.Tools {
		if t == tool {
			return true
		}
	}
	return false
}

// MatchesRequirements checks if the agent matches the given requirements.
func (a *Agent) MatchesRequirements(capabilities []string, tool string) bool {
	for _, reqCap := range capabilities {
		if !a.HasCapability(reqCap) {
			return false
		}
	}
	if tool != "" && !a.HasTool(tool) {
		return false
	}
	return true
}

// IsAvailable checks if the agent is available for work.
func (a *Agent) IsAvailable() bool {
	return a.Status == AgentStatusActive
}

// IsDaemon checks if the agent is a daemon (polls for commands).
func (a *Agent) IsDaemon() bool {
	return a.ExecutionMode == ExecutionModeDaemon || a.Type.IsWorker() || a.Type.IsCollector()
}

// IsOneShot checks if the agent is a one-shot runner (CI/CD).
func (a *Agent) IsOneShot() bool {
	return a.ExecutionMode == ExecutionModeStandalone || a.Type.IsRunner()
}

// SetMaxConcurrentJobs sets the maximum number of concurrent jobs.
func (a *Agent) SetMaxConcurrentJobs(max int) {
	a.MaxConcurrentJobs = max
	a.UpdatedAt = time.Now()
}

// AvailableSlots returns the number of available job slots.
func (a *Agent) AvailableSlots() int {
	if a.MaxConcurrentJobs <= 0 {
		return 1 // Default to 1 if not set
	}
	slots := a.MaxConcurrentJobs - a.CurrentJobs
	if slots < 0 {
		return 0
	}
	return slots
}

// LoadFactor returns the current load factor (0.0 to 1.0).
func (a *Agent) LoadFactor() float64 {
	if a.MaxConcurrentJobs <= 0 {
		return 0
	}
	return float64(a.CurrentJobs) / float64(a.MaxConcurrentJobs)
}

// HasCapacity checks if the agent has capacity for more jobs.
func (a *Agent) HasCapacity() bool {
	if a.MaxConcurrentJobs <= 0 {
		return true // No limit set
	}
	return a.CurrentJobs < a.MaxConcurrentJobs
}

// SetPlatformAgent marks this agent as a platform-managed agent.
// Platform agents don't count towards tenant's agent limit.
func (a *Agent) SetPlatformAgent(isPlatform bool) {
	a.IsPlatformAgent = isPlatform
	a.UpdatedAt = time.Now()
}

// CanExecutePlatformJob checks if this platform agent can execute a job
// with the given requirements.
func (a *Agent) CanExecutePlatformJob(capabilities []string, tool, preferredRegion string) bool {
	if !a.IsPlatformAgent {
		return false
	}
	if !a.IsAvailable() || a.Health != AgentHealthOnline {
		return false
	}
	if !a.HasCapacity() {
		return false
	}
	if !a.MatchesRequirements(capabilities, tool) {
		return false
	}
	// Region is a soft preference, not a hard requirement
	return true
}

// ScoreForJob calculates a score for job matching (higher is better).
// Used for selecting the best platform agent for a job.
func (a *Agent) ScoreForJob(capabilities []string, tool, preferredRegion string) int {
	if !a.CanExecutePlatformJob(capabilities, tool, preferredRegion) {
		return -1
	}

	score := 100

	// Prefer agents with more available capacity
	score += a.AvailableSlots() * 10

	// Prefer agents with lower load
	score -= int(a.LoadFactor() * 50)

	// Prefer agents in the preferred region
	if preferredRegion != "" && a.Region == preferredRegion {
		score += 50
	}

	return score
}
