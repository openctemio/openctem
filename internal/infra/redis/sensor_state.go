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

// SensorState key patterns for Redis.
const (
	// Key patterns
	sensorHeartbeatKey      = "agent:heartbeat:%s"       // sensor:heartbeat:{sensor_id}
	sensorStatusKey         = "agent:status:%s"          // sensor:status:{sensor_id}
	sensorJobsKey           = "agent:jobs:%s"            // sensor:jobs:{sensor_id} (sorted set)
	sensorConfigKey         = "agent:config:%s"          // sensor:config:{sensor_id} (cached config)
	sensorPrevHealthKey     = "agent:prev_health:%s"     // sensor:prev_health:{sensor_id} (previous health state)
	platformSensorOnlineKey = "platform:agents:online"   // sorted set of online platform sensors
	platformSensorStatusKey = "platform:agent:status:%s" // platform:sensor:status:{sensor_id}
	queueStatsKey           = "platform:queue:stats"     // hash with queue statistics

	// Default TTLs
	heartbeatTTL      = 2 * time.Minute  // Sensor heartbeat expires after 2 minutes
	sensorStatusTTL   = 5 * time.Minute  // Sensor status cached for 5 minutes
	sensorConfigTTL   = 30 * time.Minute // Sensor config cached for 30 minutes (avoid DB reads on every heartbeat)
	platformSensorTTL = 10 * time.Minute // Platform sensor online status TTL
)

// SensorStateStore manages ephemeral sensor state in Redis.
type SensorStateStore struct {
	client *Client
	logger *logger.Logger
}

// NewSensorStateStore creates a new SensorStateStore.
func NewSensorStateStore(client *Client, log *logger.Logger) *SensorStateStore {
	return &SensorStateStore{
		client: client,
		logger: log,
	}
}

// =============================================================================
// Sensor Heartbeat
// =============================================================================

// SensorHeartbeat represents the heartbeat data stored in Redis.
type SensorHeartbeat struct {
	SensorID      string    `json:"agent_id"`
	TenantID      string    `json:"tenant_id,omitempty"` // Empty for platform sensors
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

// RecordHeartbeat records a sensor heartbeat.
func (s *SensorStateStore) RecordHeartbeat(ctx context.Context, hb *SensorHeartbeat) error {
	key := fmt.Sprintf(sensorHeartbeatKey, hb.SensorID)
	hb.LastHeartbeat = time.Now()

	data, err := json.Marshal(hb)
	if err != nil {
		return fmt.Errorf("failed to marshal heartbeat: %w", err)
	}

	if err := s.client.Set(ctx, key, string(data), heartbeatTTL); err != nil {
		return fmt.Errorf("failed to store heartbeat: %w", err)
	}

	// If platform sensor, update online set
	if hb.IsPlatform && hb.Health == "online" {
		score := float64(time.Now().Unix())
		if err := s.client.client.ZAdd(ctx, platformSensorOnlineKey, redis.Z{
			Score:  score,
			Member: hb.SensorID,
		}).Err(); err != nil {
			s.logger.Warn("failed to update platform agent online set", "error", err)
		}
	}

	return nil
}

// GetHeartbeat retrieves the latest heartbeat for a sensor.
func (s *SensorStateStore) GetHeartbeat(ctx context.Context, sensorID shared.ID) (*SensorHeartbeat, error) {
	key := fmt.Sprintf(sensorHeartbeatKey, sensorID.String())

	data, err := s.client.Get(ctx, key)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get heartbeat: %w", err)
	}

	var hb SensorHeartbeat
	if err := json.Unmarshal([]byte(data), &hb); err != nil {
		return nil, fmt.Errorf("failed to unmarshal heartbeat: %w", err)
	}

	return &hb, nil
}

// IsSensorOnline checks if a sensor is online based on heartbeat.
func (s *SensorStateStore) IsSensorOnline(ctx context.Context, sensorID shared.ID) (bool, error) {
	hb, err := s.GetHeartbeat(ctx, sensorID)
	if err != nil {
		return false, err
	}

	if hb == nil {
		return false, nil
	}

	// Consider sensor online if heartbeat within last 2 minutes
	return time.Since(hb.LastHeartbeat) < heartbeatTTL, nil
}

// RemoveHeartbeat removes a sensor's heartbeat (for clean shutdown).
func (s *SensorStateStore) RemoveHeartbeat(ctx context.Context, sensorID shared.ID) error {
	key := fmt.Sprintf(sensorHeartbeatKey, sensorID.String())
	if err := s.client.Del(ctx, key); err != nil {
		return fmt.Errorf("failed to remove heartbeat: %w", err)
	}

	// Remove from online set
	if err := s.client.client.ZRem(ctx, platformSensorOnlineKey, sensorID.String()).Err(); err != nil {
		s.logger.Warn("failed to remove from online set", "error", err)
	}

	return nil
}

// =============================================================================
// Sensor Config Caching (Heartbeat Optimization)
// =============================================================================

// CachedSensorConfig represents the cached sensor configuration to avoid DB reads on every heartbeat.
type CachedSensorConfig struct {
	SensorID      string   `json:"agent_id"`
	TenantID      string   `json:"tenant_id,omitempty"` // Empty for platform sensors
	IsPlatform    bool     `json:"is_platform"`
	Status        string   `json:"status"` // Admin-controlled status (active, disabled, revoked)
	Capabilities  []string `json:"capabilities"`
	Tools         []string `json:"tools"`
	MaxConcurrent int      `json:"max_concurrent"`
	Region        string   `json:"region,omitempty"`
	CachedAt      int64    `json:"cached_at"` // Unix timestamp
}

// SetSensorConfig caches sensor configuration to avoid DB reads on every heartbeat.
func (s *SensorStateStore) SetSensorConfig(ctx context.Context, config *CachedSensorConfig) error {
	key := fmt.Sprintf(sensorConfigKey, config.SensorID)
	config.CachedAt = time.Now().Unix()

	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal agent config: %w", err)
	}

	if err := s.client.Set(ctx, key, string(data), sensorConfigTTL); err != nil {
		return fmt.Errorf("failed to cache agent config: %w", err)
	}

	return nil
}

// GetSensorConfig retrieves cached sensor configuration.
// Returns nil, nil if not cached (caller should load from DB and cache).
func (s *SensorStateStore) GetSensorConfig(ctx context.Context, sensorID shared.ID) (*CachedSensorConfig, error) {
	key := fmt.Sprintf(sensorConfigKey, sensorID.String())

	data, err := s.client.Get(ctx, key)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get agent config: %w", err)
	}

	var config CachedSensorConfig
	if err := json.Unmarshal([]byte(data), &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal agent config: %w", err)
	}

	return &config, nil
}

// InvalidateSensorConfig removes cached sensor configuration (e.g., after admin update).
func (s *SensorStateStore) InvalidateSensorConfig(ctx context.Context, sensorID shared.ID) error {
	key := fmt.Sprintf(sensorConfigKey, sensorID.String())
	if err := s.client.Del(ctx, key); err != nil {
		return fmt.Errorf("failed to invalidate agent config: %w", err)
	}
	return nil
}

// =============================================================================
// Sensor Health State Tracking (Heartbeat Optimization)
// =============================================================================

// GetPreviousHealthState returns the previous health state of a sensor.
// Used to detect state transitions (offline -> online, online -> offline).
func (s *SensorStateStore) GetPreviousHealthState(ctx context.Context, sensorID shared.ID) (string, error) {
	key := fmt.Sprintf(sensorPrevHealthKey, sensorID.String())

	data, err := s.client.Get(ctx, key)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return "", nil // No previous state (new sensor or first heartbeat)
		}
		return "", fmt.Errorf("failed to get previous health state: %w", err)
	}

	return data, nil
}

// SetPreviousHealthState stores the previous health state of a sensor.
// TTL is set longer than heartbeat to ensure we can detect offline -> online transitions.
func (s *SensorStateStore) SetPreviousHealthState(ctx context.Context, sensorID shared.ID, health string) error {
	key := fmt.Sprintf(sensorPrevHealthKey, sensorID.String())

	// TTL is 10 minutes - long enough to detect transitions after heartbeat timeout
	if err := s.client.Set(ctx, key, health, 10*time.Minute); err != nil {
		return fmt.Errorf("failed to set previous health state: %w", err)
	}

	return nil
}

// WasSensorOffline checks if sensor was previously offline (for detecting online transition).
// Returns true if:
// 1. Previous health state was "offline" or "error"
// 2. No previous heartbeat exists (new sensor or first heartbeat after long downtime)
func (s *SensorStateStore) WasSensorOffline(ctx context.Context, sensorID shared.ID) (bool, error) {
	prevHealth, err := s.GetPreviousHealthState(ctx, sensorID)
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

// GetLastHeartbeatTime returns the last heartbeat timestamp for a sensor.
// Returns zero time if no heartbeat exists.
func (s *SensorStateStore) GetLastHeartbeatTime(ctx context.Context, sensorID shared.ID) (time.Time, error) {
	hb, err := s.GetHeartbeat(ctx, sensorID)
	if err != nil {
		return time.Time{}, err
	}
	if hb == nil {
		return time.Time{}, nil
	}
	return hb.LastHeartbeat, nil
}

// GetSensorsWithStaleHeartbeat returns sensor IDs whose heartbeat is older than the threshold.
// Used by health monitor to detect sensors that went offline.
func (s *SensorStateStore) GetSensorsWithStaleHeartbeat(ctx context.Context, threshold time.Duration) ([]string, error) {
	// Get all sensor heartbeat keys
	pattern := "agent:heartbeat:*"
	keys, err := s.client.Scan(ctx, pattern, 1000)
	if err != nil {
		return nil, fmt.Errorf("failed to scan heartbeat keys: %w", err)
	}

	var staleSensors []string
	now := time.Now()

	for _, key := range keys {
		data, err := s.client.Get(ctx, key)
		if err != nil {
			continue
		}

		var hb SensorHeartbeat
		if err := json.Unmarshal([]byte(data), &hb); err != nil {
			continue
		}

		// Check if heartbeat is stale
		if now.Sub(hb.LastHeartbeat) > threshold {
			staleSensors = append(staleSensors, hb.SensorID)
		}
	}

	return staleSensors, nil
}

// MarkSensorOfflineInCache marks a sensor as offline in the cache.
// Called by health monitor when heartbeat timeout is detected.
func (s *SensorStateStore) MarkSensorOfflineInCache(ctx context.Context, sensorID shared.ID) error {
	// Update previous health state
	if err := s.SetPreviousHealthState(ctx, sensorID, "offline"); err != nil {
		return err
	}

	// Remove from online platform sensors set
	if err := s.client.client.ZRem(ctx, platformSensorOnlineKey, sensorID.String()).Err(); err != nil {
		s.logger.Warn("failed to remove from online set", "agent_id", sensorID, "error", err)
	}

	// Delete the heartbeat key (so TTL cleanup doesn't conflict)
	key := fmt.Sprintf(sensorHeartbeatKey, sensorID.String())
	if err := s.client.Del(ctx, key); err != nil {
		s.logger.Warn("failed to delete heartbeat key", "agent_id", sensorID, "error", err)
	}

	return nil
}

// =============================================================================
// Platform Sensor State
// =============================================================================

// PlatformSensorState represents the state of a platform sensor.
type PlatformSensorState struct {
	SensorID      string    `json:"agent_id"`
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

// SetPlatformSensorState stores the state of a platform sensor.
func (s *SensorStateStore) SetPlatformSensorState(ctx context.Context, state *PlatformSensorState) error {
	key := fmt.Sprintf(platformSensorStatusKey, state.SensorID)

	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal agent state: %w", err)
	}

	if err := s.client.Set(ctx, key, string(data), platformSensorTTL); err != nil {
		return fmt.Errorf("failed to store agent state: %w", err)
	}

	return nil
}

// GetPlatformSensorState retrieves the state of a platform sensor.
func (s *SensorStateStore) GetPlatformSensorState(ctx context.Context, sensorID shared.ID) (*PlatformSensorState, error) {
	key := fmt.Sprintf(platformSensorStatusKey, sensorID.String())

	data, err := s.client.Get(ctx, key)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get agent state: %w", err)
	}

	var state PlatformSensorState
	if err := json.Unmarshal([]byte(data), &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal agent state: %w", err)
	}

	return &state, nil
}

// GetOnlinePlatformSensors returns all online platform sensor IDs.
func (s *SensorStateStore) GetOnlinePlatformSensors(ctx context.Context) ([]string, error) {
	// Clean up stale entries first (older than 10 minutes)
	cutoff := float64(time.Now().Add(-platformSensorTTL).Unix())
	s.client.client.ZRemRangeByScore(ctx, platformSensorOnlineKey, "-inf", strconv.FormatFloat(cutoff, 'f', 0, 64))

	// Get all remaining
	members, err := s.client.client.ZRangeArgs(ctx, redis.ZRangeArgs{
		Key:     platformSensorOnlineKey,
		Start:   "-inf",
		Stop:    "+inf",
		ByScore: true,
	}).Result()

	if err != nil {
		return nil, fmt.Errorf("failed to get online agents: %w", err)
	}

	return members, nil
}

// GetOnlinePlatformSensorCount returns the count of online platform sensors.
func (s *SensorStateStore) GetOnlinePlatformSensorCount(ctx context.Context) (int64, error) {
	// Clean up stale entries first
	cutoff := float64(time.Now().Add(-platformSensorTTL).Unix())
	s.client.client.ZRemRangeByScore(ctx, platformSensorOnlineKey, "-inf", strconv.FormatFloat(cutoff, 'f', 0, 64))

	count, err := s.client.client.ZCard(ctx, platformSensorOnlineKey).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to count online agents: %w", err)
	}

	return count, nil
}

// =============================================================================
// Sensor Job Tracking
// =============================================================================

// TrackSensorJob adds a job to a sensor's active job set.
func (s *SensorStateStore) TrackSensorJob(ctx context.Context, sensorID, jobID shared.ID) error {
	key := fmt.Sprintf(sensorJobsKey, sensorID.String())
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

// UntrackSensorJob removes a job from a sensor's active job set.
func (s *SensorStateStore) UntrackSensorJob(ctx context.Context, sensorID, jobID shared.ID) error {
	key := fmt.Sprintf(sensorJobsKey, sensorID.String())

	if err := s.client.client.ZRem(ctx, key, jobID.String()).Err(); err != nil {
		return fmt.Errorf("failed to untrack job: %w", err)
	}

	return nil
}

// GetSensorActiveJobs returns all active job IDs for a sensor.
func (s *SensorStateStore) GetSensorActiveJobs(ctx context.Context, sensorID shared.ID) ([]string, error) {
	key := fmt.Sprintf(sensorJobsKey, sensorID.String())

	jobs, err := s.client.client.ZRange(ctx, key, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get active jobs: %w", err)
	}

	return jobs, nil
}

// GetSensorActiveJobCount returns the count of active jobs for a sensor.
func (s *SensorStateStore) GetSensorActiveJobCount(ctx context.Context, sensorID shared.ID) (int64, error) {
	key := fmt.Sprintf(sensorJobsKey, sensorID.String())

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
func (s *SensorStateStore) UpdateQueueStats(ctx context.Context, stats *QueueStats) error {
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
func (s *SensorStateStore) GetQueueStats(ctx context.Context) (*QueueStats, error) {
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
func (s *SensorStateStore) IncrementQueueStat(ctx context.Context, field string, delta int64) error {
	if err := s.client.client.HIncrBy(ctx, queueStatsKey, field, delta).Err(); err != nil {
		return fmt.Errorf("failed to increment queue stat: %w", err)
	}
	return nil
}

// =============================================================================
// Cleanup
// =============================================================================

// CleanupStaleSensors removes stale sensor data from Redis.
func (s *SensorStateStore) CleanupStaleSensors(ctx context.Context, threshold time.Duration) (int, error) {
	// Get all sensor heartbeat keys
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

		var hb SensorHeartbeat
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

	// Clean up platform sensor online set
	cutoff := float64(time.Now().Add(-threshold).Unix())
	removed, _ := s.client.client.ZRemRangeByScore(ctx, platformSensorOnlineKey, "-inf", strconv.FormatFloat(cutoff, 'f', 0, 64)).Result()
	cleaned += int(removed)

	return cleaned, nil
}
