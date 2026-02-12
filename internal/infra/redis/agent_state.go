package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// AgentState key patterns for Redis.
const (
	// Key patterns
	agentHeartbeatKey      = "agent:heartbeat:%s"       // agent:heartbeat:{agent_id}
	agentStatusKey         = "agent:status:%s"          // agent:status:{agent_id}
	agentJobsKey           = "agent:jobs:%s"            // agent:jobs:{agent_id} (sorted set)
	agentConfigKey         = "agent:config:%s"          // agent:config:{agent_id} (cached config)
	agentPrevHealthKey     = "agent:prev_health:%s"     // agent:prev_health:{agent_id} (previous health state)
	platformAgentOnlineKey = "platform:agents:online"   // sorted set of online platform agents
	platformAgentStatusKey = "platform:agent:status:%s" // platform:agent:status:{agent_id}
	queueStatsKey          = "platform:queue:stats"     // hash with queue statistics

	// Default TTLs
	heartbeatTTL     = 2 * time.Minute  // Agent heartbeat expires after 2 minutes
	agentStatusTTL   = 5 * time.Minute  // Agent status cached for 5 minutes
	agentConfigTTL   = 30 * time.Minute // Agent config cached for 30 minutes (avoid DB reads on every heartbeat)
	platformAgentTTL = 10 * time.Minute // Platform agent online status TTL
)

// AgentStateStore manages ephemeral agent state in Redis.
type AgentStateStore struct {
	client *Client
	logger *logger.Logger
}

// NewAgentStateStore creates a new AgentStateStore.
func NewAgentStateStore(client *Client, log *logger.Logger) *AgentStateStore {
	return &AgentStateStore{
		client: client,
		logger: log,
	}
}

// =============================================================================
// Agent Heartbeat
// =============================================================================

// AgentHeartbeat represents the heartbeat data stored in Redis.
type AgentHeartbeat struct {
	AgentID       string    `json:"agent_id"`
	TenantID      string    `json:"tenant_id,omitempty"` // Empty for platform agents
	IsPlatform    bool      `json:"is_platform"`
	Status        string    `json:"status"`
	Health        string    `json:"health"`
	CurrentJobs   int       `json:"current_jobs"`
	MaxConcurrent int       `json:"max_concurrent"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	IPAddress     string    `json:"ip_address,omitempty"`
	Region        string    `json:"region,omitempty"`
	Version       string    `json:"version,omitempty"`
	// Extended metrics for load balancing
	CPUPercent    float64 `json:"cpu_percent,omitempty"`
	MemoryPercent float64 `json:"memory_percent,omitempty"`
	LoadScore     float64 `json:"load_score,omitempty"` // Weighted load score (lower is better)
}

// RecordHeartbeat records an agent heartbeat.
func (s *AgentStateStore) RecordHeartbeat(ctx context.Context, hb *AgentHeartbeat) error {
	key := fmt.Sprintf(agentHeartbeatKey, hb.AgentID)
	hb.LastHeartbeat = time.Now()

	data, err := json.Marshal(hb)
	if err != nil {
		return fmt.Errorf("failed to marshal heartbeat: %w", err)
	}

	if err := s.client.Set(ctx, key, string(data), heartbeatTTL); err != nil {
		return fmt.Errorf("failed to store heartbeat: %w", err)
	}

	// If platform agent, update online set
	if hb.IsPlatform && hb.Health == "online" {
		score := float64(time.Now().Unix())
		if err := s.client.client.ZAdd(ctx, platformAgentOnlineKey, redis.Z{
			Score:  score,
			Member: hb.AgentID,
		}).Err(); err != nil {
			s.logger.Warn("failed to update platform agent online set", "error", err)
		}
	}

	return nil
}

// GetHeartbeat retrieves the latest heartbeat for an agent.
func (s *AgentStateStore) GetHeartbeat(ctx context.Context, agentID shared.ID) (*AgentHeartbeat, error) {
	key := fmt.Sprintf(agentHeartbeatKey, agentID.String())

	data, err := s.client.Get(ctx, key)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get heartbeat: %w", err)
	}

	var hb AgentHeartbeat
	if err := json.Unmarshal([]byte(data), &hb); err != nil {
		return nil, fmt.Errorf("failed to unmarshal heartbeat: %w", err)
	}

	return &hb, nil
}

// IsAgentOnline checks if an agent is online based on heartbeat.
func (s *AgentStateStore) IsAgentOnline(ctx context.Context, agentID shared.ID) (bool, error) {
	hb, err := s.GetHeartbeat(ctx, agentID)
	if err != nil {
		return false, err
	}

	if hb == nil {
		return false, nil
	}

	// Consider agent online if heartbeat within last 2 minutes
	return time.Since(hb.LastHeartbeat) < heartbeatTTL, nil
}

// RemoveHeartbeat removes an agent's heartbeat (for clean shutdown).
func (s *AgentStateStore) RemoveHeartbeat(ctx context.Context, agentID shared.ID) error {
	key := fmt.Sprintf(agentHeartbeatKey, agentID.String())
	if err := s.client.Del(ctx, key); err != nil {
		return fmt.Errorf("failed to remove heartbeat: %w", err)
	}

	// Remove from online set
	if err := s.client.client.ZRem(ctx, platformAgentOnlineKey, agentID.String()).Err(); err != nil {
		s.logger.Warn("failed to remove from online set", "error", err)
	}

	return nil
}

// =============================================================================
// Agent Config Caching (Heartbeat Optimization)
// =============================================================================

// CachedAgentConfig represents the cached agent configuration to avoid DB reads on every heartbeat.
type CachedAgentConfig struct {
	AgentID       string   `json:"agent_id"`
	TenantID      string   `json:"tenant_id,omitempty"` // Empty for platform agents
	IsPlatform    bool     `json:"is_platform"`
	Status        string   `json:"status"` // Admin-controlled status (active, disabled, revoked)
	Capabilities  []string `json:"capabilities"`
	Tools         []string `json:"tools"`
	MaxConcurrent int      `json:"max_concurrent"`
	Region        string   `json:"region,omitempty"`
	CachedAt      int64    `json:"cached_at"` // Unix timestamp
}

// SetAgentConfig caches agent configuration to avoid DB reads on every heartbeat.
func (s *AgentStateStore) SetAgentConfig(ctx context.Context, config *CachedAgentConfig) error {
	key := fmt.Sprintf(agentConfigKey, config.AgentID)
	config.CachedAt = time.Now().Unix()

	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal agent config: %w", err)
	}

	if err := s.client.Set(ctx, key, string(data), agentConfigTTL); err != nil {
		return fmt.Errorf("failed to cache agent config: %w", err)
	}

	return nil
}

// GetAgentConfig retrieves cached agent configuration.
// Returns nil, nil if not cached (caller should load from DB and cache).
func (s *AgentStateStore) GetAgentConfig(ctx context.Context, agentID shared.ID) (*CachedAgentConfig, error) {
	key := fmt.Sprintf(agentConfigKey, agentID.String())

	data, err := s.client.Get(ctx, key)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get agent config: %w", err)
	}

	var config CachedAgentConfig
	if err := json.Unmarshal([]byte(data), &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal agent config: %w", err)
	}

	return &config, nil
}

// InvalidateAgentConfig removes cached agent configuration (e.g., after admin update).
func (s *AgentStateStore) InvalidateAgentConfig(ctx context.Context, agentID shared.ID) error {
	key := fmt.Sprintf(agentConfigKey, agentID.String())
	if err := s.client.Del(ctx, key); err != nil {
		return fmt.Errorf("failed to invalidate agent config: %w", err)
	}
	return nil
}

// =============================================================================
// Agent Health State Tracking (Heartbeat Optimization)
// =============================================================================

// GetPreviousHealthState returns the previous health state of an agent.
// Used to detect state transitions (offline -> online, online -> offline).
func (s *AgentStateStore) GetPreviousHealthState(ctx context.Context, agentID shared.ID) (string, error) {
	key := fmt.Sprintf(agentPrevHealthKey, agentID.String())

	data, err := s.client.Get(ctx, key)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return "", nil // No previous state (new agent or first heartbeat)
		}
		return "", fmt.Errorf("failed to get previous health state: %w", err)
	}

	return data, nil
}

// SetPreviousHealthState stores the previous health state of an agent.
// TTL is set longer than heartbeat to ensure we can detect offline -> online transitions.
func (s *AgentStateStore) SetPreviousHealthState(ctx context.Context, agentID shared.ID, health string) error {
	key := fmt.Sprintf(agentPrevHealthKey, agentID.String())

	// TTL is 10 minutes - long enough to detect transitions after heartbeat timeout
	if err := s.client.Set(ctx, key, health, 10*time.Minute); err != nil {
		return fmt.Errorf("failed to set previous health state: %w", err)
	}

	return nil
}

// WasAgentOffline checks if agent was previously offline (for detecting online transition).
// Returns true if:
// 1. Previous health state was "offline" or "error"
// 2. No previous heartbeat exists (new agent or first heartbeat after long downtime)
func (s *AgentStateStore) WasAgentOffline(ctx context.Context, agentID shared.ID) (bool, error) {
	prevHealth, err := s.GetPreviousHealthState(ctx, agentID)
	if err != nil {
		return false, err
	}

	// No previous state = consider as coming online
	if prevHealth == "" {
		return true, nil
	}

	// Was offline or error = now coming online
	return prevHealth == "offline" || prevHealth == "error" || prevHealth == "unknown", nil
}

// GetLastHeartbeatTime returns the last heartbeat timestamp for an agent.
// Returns zero time if no heartbeat exists.
func (s *AgentStateStore) GetLastHeartbeatTime(ctx context.Context, agentID shared.ID) (time.Time, error) {
	hb, err := s.GetHeartbeat(ctx, agentID)
	if err != nil {
		return time.Time{}, err
	}
	if hb == nil {
		return time.Time{}, nil
	}
	return hb.LastHeartbeat, nil
}

// GetAgentsWithStaleHeartbeat returns agent IDs whose heartbeat is older than the threshold.
// Used by health monitor to detect agents that went offline.
func (s *AgentStateStore) GetAgentsWithStaleHeartbeat(ctx context.Context, threshold time.Duration) ([]string, error) {
	// Get all agent heartbeat keys
	pattern := "agent:heartbeat:*"
	keys, err := s.client.Scan(ctx, pattern, 1000)
	if err != nil {
		return nil, fmt.Errorf("failed to scan heartbeat keys: %w", err)
	}

	var staleAgents []string
	now := time.Now()

	for _, key := range keys {
		data, err := s.client.Get(ctx, key)
		if err != nil {
			continue
		}

		var hb AgentHeartbeat
		if err := json.Unmarshal([]byte(data), &hb); err != nil {
			continue
		}

		// Check if heartbeat is stale
		if now.Sub(hb.LastHeartbeat) > threshold {
			staleAgents = append(staleAgents, hb.AgentID)
		}
	}

	return staleAgents, nil
}

// MarkAgentOfflineInCache marks an agent as offline in the cache.
// Called by health monitor when heartbeat timeout is detected.
func (s *AgentStateStore) MarkAgentOfflineInCache(ctx context.Context, agentID shared.ID) error {
	// Update previous health state
	if err := s.SetPreviousHealthState(ctx, agentID, "offline"); err != nil {
		return err
	}

	// Remove from online platform agents set
	if err := s.client.client.ZRem(ctx, platformAgentOnlineKey, agentID.String()).Err(); err != nil {
		s.logger.Warn("failed to remove from online set", "agent_id", agentID, "error", err)
	}

	// Delete the heartbeat key (so TTL cleanup doesn't conflict)
	key := fmt.Sprintf(agentHeartbeatKey, agentID.String())
	if err := s.client.Del(ctx, key); err != nil {
		s.logger.Warn("failed to delete heartbeat key", "agent_id", agentID, "error", err)
	}

	return nil
}

// =============================================================================
// Platform Agent State
// =============================================================================

// PlatformAgentState represents the state of a platform agent.
type PlatformAgentState struct {
	AgentID       string    `json:"agent_id"`
	Health        string    `json:"health"`
	CurrentJobs   int       `json:"current_jobs"`
	MaxConcurrent int       `json:"max_concurrent"`
	Region        string    `json:"region"`
	Capabilities  []string  `json:"capabilities"`
	Tools         []string  `json:"tools"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	LastJobAt     time.Time `json:"last_job_at,omitempty"`
	TotalJobs     int64     `json:"total_jobs"`
	FailedJobs    int64     `json:"failed_jobs"`
	// Extended metrics for load balancing
	CPUPercent    float64 `json:"cpu_percent,omitempty"`
	MemoryPercent float64 `json:"memory_percent,omitempty"`
	LoadScore     float64 `json:"load_score,omitempty"` // Weighted load score (lower is better)
}

// SetPlatformAgentState stores the state of a platform agent.
func (s *AgentStateStore) SetPlatformAgentState(ctx context.Context, state *PlatformAgentState) error {
	key := fmt.Sprintf(platformAgentStatusKey, state.AgentID)

	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal agent state: %w", err)
	}

	if err := s.client.Set(ctx, key, string(data), platformAgentTTL); err != nil {
		return fmt.Errorf("failed to store agent state: %w", err)
	}

	return nil
}

// GetPlatformAgentState retrieves the state of a platform agent.
func (s *AgentStateStore) GetPlatformAgentState(ctx context.Context, agentID shared.ID) (*PlatformAgentState, error) {
	key := fmt.Sprintf(platformAgentStatusKey, agentID.String())

	data, err := s.client.Get(ctx, key)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get agent state: %w", err)
	}

	var state PlatformAgentState
	if err := json.Unmarshal([]byte(data), &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal agent state: %w", err)
	}

	return &state, nil
}

// GetOnlinePlatformAgents returns all online platform agent IDs.
func (s *AgentStateStore) GetOnlinePlatformAgents(ctx context.Context) ([]string, error) {
	// Clean up stale entries first (older than 10 minutes)
	cutoff := float64(time.Now().Add(-platformAgentTTL).Unix())
	s.client.client.ZRemRangeByScore(ctx, platformAgentOnlineKey, "-inf", strconv.FormatFloat(cutoff, 'f', 0, 64))

	// Get all remaining
	members, err := s.client.client.ZRangeByScore(ctx, platformAgentOnlineKey, &redis.ZRangeBy{
		Min: "-inf",
		Max: "+inf",
	}).Result()

	if err != nil {
		return nil, fmt.Errorf("failed to get online agents: %w", err)
	}

	return members, nil
}

// GetOnlinePlatformAgentCount returns the count of online platform agents.
func (s *AgentStateStore) GetOnlinePlatformAgentCount(ctx context.Context) (int64, error) {
	// Clean up stale entries first
	cutoff := float64(time.Now().Add(-platformAgentTTL).Unix())
	s.client.client.ZRemRangeByScore(ctx, platformAgentOnlineKey, "-inf", strconv.FormatFloat(cutoff, 'f', 0, 64))

	count, err := s.client.client.ZCard(ctx, platformAgentOnlineKey).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to count online agents: %w", err)
	}

	return count, nil
}

// =============================================================================
// Agent Job Tracking
// =============================================================================

// TrackAgentJob adds a job to an agent's active job set.
func (s *AgentStateStore) TrackAgentJob(ctx context.Context, agentID, jobID shared.ID) error {
	key := fmt.Sprintf(agentJobsKey, agentID.String())
	score := float64(time.Now().Unix())

	if err := s.client.client.ZAdd(ctx, key, redis.Z{
		Score:  score,
		Member: jobID.String(),
	}).Err(); err != nil {
		return fmt.Errorf("failed to track job: %w", err)
	}

	// Set TTL on the set
	if err := s.client.Expire(ctx, key, 24*time.Hour); err != nil {
		return fmt.Errorf("failed to expire job key: %w", err)
	}

	return nil
}

// UntrackAgentJob removes a job from an agent's active job set.
func (s *AgentStateStore) UntrackAgentJob(ctx context.Context, agentID, jobID shared.ID) error {
	key := fmt.Sprintf(agentJobsKey, agentID.String())

	if err := s.client.client.ZRem(ctx, key, jobID.String()).Err(); err != nil {
		return fmt.Errorf("failed to untrack job: %w", err)
	}

	return nil
}

// GetAgentActiveJobs returns all active job IDs for an agent.
func (s *AgentStateStore) GetAgentActiveJobs(ctx context.Context, agentID shared.ID) ([]string, error) {
	key := fmt.Sprintf(agentJobsKey, agentID.String())

	jobs, err := s.client.client.ZRange(ctx, key, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get active jobs: %w", err)
	}

	return jobs, nil
}

// GetAgentActiveJobCount returns the count of active jobs for an agent.
func (s *AgentStateStore) GetAgentActiveJobCount(ctx context.Context, agentID shared.ID) (int64, error) {
	key := fmt.Sprintf(agentJobsKey, agentID.String())

	count, err := s.client.client.ZCard(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to count active jobs: %w", err)
	}

	return count, nil
}

// =============================================================================
// Queue Statistics
// =============================================================================

// QueueStats represents queue statistics.
type QueueStats struct {
	TotalQueued       int64     `json:"total_queued"`
	TotalProcessing   int64     `json:"total_processing"`
	TotalCompleted    int64     `json:"total_completed"`
	TotalFailed       int64     `json:"total_failed"`
	AvgWaitTimeSec    float64   `json:"avg_wait_time_sec"`
	AvgProcessTimeSec float64   `json:"avg_process_time_sec"`
	LastUpdated       time.Time `json:"last_updated"`
}

// UpdateQueueStats updates queue statistics.
func (s *AgentStateStore) UpdateQueueStats(ctx context.Context, stats *QueueStats) error {
	stats.LastUpdated = time.Now()

	fields := map[string]interface{}{
		"total_queued":         stats.TotalQueued,
		"total_processing":     stats.TotalProcessing,
		"total_completed":      stats.TotalCompleted,
		"total_failed":         stats.TotalFailed,
		"avg_wait_time_sec":    stats.AvgWaitTimeSec,
		"avg_process_time_sec": stats.AvgProcessTimeSec,
		"last_updated":         stats.LastUpdated.Unix(),
	}

	if err := s.client.client.HSet(ctx, queueStatsKey, fields).Err(); err != nil {
		return fmt.Errorf("failed to update queue stats: %w", err)
	}

	return nil
}

// GetQueueStats retrieves queue statistics.
func (s *AgentStateStore) GetQueueStats(ctx context.Context) (*QueueStats, error) {
	result, err := s.client.client.HGetAll(ctx, queueStatsKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get queue stats: %w", err)
	}

	if len(result) == 0 {
		return &QueueStats{}, nil
	}

	stats := &QueueStats{}

	if v, ok := result["total_queued"]; ok {
		stats.TotalQueued, _ = strconv.ParseInt(v, 10, 64)
	}
	if v, ok := result["total_processing"]; ok {
		stats.TotalProcessing, _ = strconv.ParseInt(v, 10, 64)
	}
	if v, ok := result["total_completed"]; ok {
		stats.TotalCompleted, _ = strconv.ParseInt(v, 10, 64)
	}
	if v, ok := result["total_failed"]; ok {
		stats.TotalFailed, _ = strconv.ParseInt(v, 10, 64)
	}
	if v, ok := result["avg_wait_time_sec"]; ok {
		stats.AvgWaitTimeSec, _ = strconv.ParseFloat(v, 64)
	}
	if v, ok := result["avg_process_time_sec"]; ok {
		stats.AvgProcessTimeSec, _ = strconv.ParseFloat(v, 64)
	}
	if v, ok := result["last_updated"]; ok {
		ts, _ := strconv.ParseInt(v, 10, 64)
		stats.LastUpdated = time.Unix(ts, 0)
	}

	return stats, nil
}

// IncrementQueueStat increments a specific queue stat counter.
func (s *AgentStateStore) IncrementQueueStat(ctx context.Context, field string, delta int64) error {
	if err := s.client.client.HIncrBy(ctx, queueStatsKey, field, delta).Err(); err != nil {
		return fmt.Errorf("failed to increment queue stat: %w", err)
	}
	return nil
}

// =============================================================================
// Cleanup
// =============================================================================

// CleanupStaleAgents removes stale agent data from Redis.
func (s *AgentStateStore) CleanupStaleAgents(ctx context.Context, threshold time.Duration) (int, error) {
	// Get all agent heartbeat keys
	pattern := "agent:heartbeat:*"
	keys, err := s.client.Scan(ctx, pattern, 100)
	if err != nil {
		return 0, fmt.Errorf("failed to scan heartbeat keys: %w", err)
	}

	var cleaned int
	now := time.Now()

	for _, key := range keys {
		data, err := s.client.Get(ctx, key)
		if err != nil {
			continue
		}

		var hb AgentHeartbeat
		if err := json.Unmarshal([]byte(data), &hb); err != nil {
			continue
		}

		if now.Sub(hb.LastHeartbeat) > threshold {
			if err := s.client.Del(ctx, key); err != nil {
				s.logger.Warn("failed to delete heartbeat key", "key", key, "error", err)
			}
			cleaned++
		}
	}

	// Clean up platform agent online set
	cutoff := float64(time.Now().Add(-threshold).Unix())
	removed, _ := s.client.client.ZRemRangeByScore(ctx, platformAgentOnlineKey, "-inf", strconv.FormatFloat(cutoff, 'f', 0, 64)).Result()
	cleaned += int(removed)

	return cleaned, nil
}
