package jobs

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
)

const (
	// TypeEPSSRefresh refreshes EPSS scores from FIRST.org API.
	TypeEPSSRefresh = "threat_intel:epss_refresh"

	// TypeKEVRefresh refreshes CISA Known Exploited Vulnerabilities catalog.
	TypeKEVRefresh = "threat_intel:kev_refresh"

	// TypeThreatEscalation checks findings against KEV and auto-escalates.
	TypeThreatEscalation = "threat_intel:escalation_check"
)

// EPSSRefreshPayload contains config for the EPSS refresh job.
type EPSSRefreshPayload struct {
	TenantID string `json:"tenant_id,omitempty"` // Empty = all tenants
}

// KEVRefreshPayload contains config for the KEV refresh job.
type KEVRefreshPayload struct {
	TenantID string `json:"tenant_id,omitempty"`
}

// ThreatEscalationPayload contains config for the escalation check.
type ThreatEscalationPayload struct {
	TenantID string `json:"tenant_id"`
}

// NewEPSSRefreshTask creates a task to refresh EPSS scores.
func NewEPSSRefreshTask(payload EPSSRefreshPayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}
	return asynq.NewTask(
		TypeEPSSRefresh,
		data,
		asynq.MaxRetry(3),
		asynq.Timeout(10*time.Minute),
		asynq.Queue("maintenance"),
	), nil
}

// NewKEVRefreshTask creates a task to refresh CISA KEV catalog.
func NewKEVRefreshTask(payload KEVRefreshPayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}
	return asynq.NewTask(
		TypeKEVRefresh,
		data,
		asynq.MaxRetry(3),
		asynq.Timeout(10*time.Minute),
		asynq.Queue("maintenance"),
	), nil
}

// NewThreatEscalationTask creates a task to check and escalate findings.
func NewThreatEscalationTask(payload ThreatEscalationPayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}
	return asynq.NewTask(
		TypeThreatEscalation,
		data,
		asynq.MaxRetry(2),
		asynq.Timeout(5*time.Minute),
		asynq.Queue("maintenance"),
	), nil
}
