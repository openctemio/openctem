package threatintel

import (
	"fmt"
	"strings"
)

// SyncState represents the state of a sync operation.
type SyncState string

const (
	SyncStatePending SyncState = "pending"
	SyncStateRunning SyncState = "running"
	SyncStateSuccess SyncState = "success"
	SyncStateFailed  SyncState = "failed"
)

// AllSyncStates returns all valid sync states.
func AllSyncStates() []SyncState {
	return []SyncState{
		SyncStatePending,
		SyncStateRunning,
		SyncStateSuccess,
		SyncStateFailed,
	}
}

// IsValid checks if the sync state is valid.
func (s SyncState) IsValid() bool {
	switch s {
	case SyncStatePending, SyncStateRunning, SyncStateSuccess, SyncStateFailed:
		return true
	default:
		return false
	}
}

// String returns the string representation.
func (s SyncState) String() string {
	return string(s)
}

// ParseSyncState parses a string into a SyncState.
func ParseSyncState(s string) (SyncState, error) {
	state := SyncState(strings.ToLower(strings.TrimSpace(s)))
	if !state.IsValid() {
		return SyncStatePending, fmt.Errorf("invalid sync state: %s", s)
	}
	return state, nil
}

// ThreatIntelSource represents a threat intelligence source.
type ThreatIntelSource string

const (
	SourceEPSS ThreatIntelSource = "epss"
	SourceKEV  ThreatIntelSource = "kev"
)

// AllSources returns all threat intel sources.
func AllSources() []ThreatIntelSource {
	return []ThreatIntelSource{SourceEPSS, SourceKEV}
}

// IsValid checks if the source is valid.
func (t ThreatIntelSource) IsValid() bool {
	switch t {
	case SourceEPSS, SourceKEV:
		return true
	default:
		return false
	}
}

// String returns the string representation.
func (t ThreatIntelSource) String() string {
	return string(t)
}

// EPSSRiskLevel represents EPSS-based risk levels.
type EPSSRiskLevel string

const (
	EPSSRiskLevelLow      EPSSRiskLevel = "low"      // < 0.05 (5%)
	EPSSRiskLevelMedium   EPSSRiskLevel = "medium"   // 0.05 - 0.1 (5-10%)
	EPSSRiskLevelHigh     EPSSRiskLevel = "high"     // 0.1 - 0.3 (10-30%)
	EPSSRiskLevelCritical EPSSRiskLevel = "critical" // > 0.3 (30%)
)

// EPSSRiskLevelFromScore returns the risk level for an EPSS score.
func EPSSRiskLevelFromScore(score float64) EPSSRiskLevel {
	switch {
	case score >= 0.3:
		return EPSSRiskLevelCritical
	case score >= 0.1:
		return EPSSRiskLevelHigh
	case score >= 0.05:
		return EPSSRiskLevelMedium
	default:
		return EPSSRiskLevelLow
	}
}

// String returns the string representation.
func (e EPSSRiskLevel) String() string {
	return string(e)
}

// ThreatIntelEnrichment contains enrichment data for a CVE.
type ThreatIntelEnrichment struct {
	CVEID          string
	EPSSScore      *float64
	EPSSPercentile *float64
	InKEV          bool
	KEVDateAdded   *string
	KEVDueDate     *string
	KEVRansomware  *string
}

// NewThreatIntelEnrichment creates a new enrichment result.
func NewThreatIntelEnrichment(cveID string) *ThreatIntelEnrichment {
	return &ThreatIntelEnrichment{
		CVEID: cveID,
	}
}

// WithEPSS adds EPSS data.
func (t *ThreatIntelEnrichment) WithEPSS(score, percentile float64) *ThreatIntelEnrichment {
	t.EPSSScore = &score
	t.EPSSPercentile = &percentile
	return t
}

// WithKEV adds KEV data.
func (t *ThreatIntelEnrichment) WithKEV(dateAdded, dueDate, ransomware string) *ThreatIntelEnrichment {
	t.InKEV = true
	t.KEVDateAdded = &dateAdded
	t.KEVDueDate = &dueDate
	t.KEVRansomware = &ransomware
	return t
}

// HasData returns true if any enrichment data exists.
func (t *ThreatIntelEnrichment) HasData() bool {
	return t.EPSSScore != nil || t.InKEV
}

// RiskLevel returns the combined risk level.
func (t *ThreatIntelEnrichment) RiskLevel() string {
	// KEV entries are always high priority
	if t.InKEV {
		return "critical"
	}

	// EPSS-based risk level
	if t.EPSSScore != nil {
		return EPSSRiskLevelFromScore(*t.EPSSScore).String()
	}

	return "unknown"
}
