// Package threatintel provides the threat intelligence domain model.
package threatintel

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// EPSSScore represents an EPSS score entry from FIRST.org.
type EPSSScore struct {
	cveID        string
	epssScore    float64
	percentile   float64
	modelVersion string
	scoreDate    time.Time
	createdAt    time.Time
	updatedAt    time.Time
}

// NewEPSSScore creates a new EPSSScore.
func NewEPSSScore(cveID string, score, percentile float64, modelVersion string, scoreDate time.Time) *EPSSScore {
	now := time.Now().UTC()
	return &EPSSScore{
		cveID:        cveID,
		epssScore:    score,
		percentile:   percentile,
		modelVersion: modelVersion,
		scoreDate:    scoreDate,
		createdAt:    now,
		updatedAt:    now,
	}
}

// ReconstituteEPSSScore recreates an EPSSScore from persistence.
func ReconstituteEPSSScore(
	cveID string,
	score, percentile float64,
	modelVersion string,
	scoreDate time.Time,
	createdAt, updatedAt time.Time,
) *EPSSScore {
	return &EPSSScore{
		cveID:        cveID,
		epssScore:    score,
		percentile:   percentile,
		modelVersion: modelVersion,
		scoreDate:    scoreDate,
		createdAt:    createdAt,
		updatedAt:    updatedAt,
	}
}

// Getters

// CVEID returns the CVE ID.
func (e *EPSSScore) CVEID() string { return e.cveID }

// Score returns the EPSS score (0.0 to 1.0).
func (e *EPSSScore) Score() float64 { return e.epssScore }

// Percentile returns the percentile rank.
func (e *EPSSScore) Percentile() float64 { return e.percentile }

// ModelVersion returns the EPSS model version.
func (e *EPSSScore) ModelVersion() string { return e.modelVersion }

// ScoreDate returns the date of the score.
func (e *EPSSScore) ScoreDate() time.Time { return e.scoreDate }

// CreatedAt returns the creation time.
func (e *EPSSScore) CreatedAt() time.Time { return e.createdAt }

// UpdatedAt returns the last update time.
func (e *EPSSScore) UpdatedAt() time.Time { return e.updatedAt }

// IsHighRisk returns true if EPSS score indicates high risk (> 0.1 or 10%).
func (e *EPSSScore) IsHighRisk() bool { return e.epssScore > 0.1 }

// IsCriticalRisk returns true if EPSS score indicates critical risk (> 0.3 or 30%).
func (e *EPSSScore) IsCriticalRisk() bool { return e.epssScore > 0.3 }

// IsTopPercentile returns true if in top N percentile.
func (e *EPSSScore) IsTopPercentile(n float64) bool { return e.percentile >= (100.0 - n) }

// Update updates the score values.
func (e *EPSSScore) Update(score, percentile float64, modelVersion string, scoreDate time.Time) {
	e.epssScore = score
	e.percentile = percentile
	e.modelVersion = modelVersion
	e.scoreDate = scoreDate
	e.updatedAt = time.Now().UTC()
}

// KEVEntry represents a CISA Known Exploited Vulnerability entry.
type KEVEntry struct {
	cveID                      string
	vendorProject              string
	product                    string
	vulnerabilityName          string
	shortDescription           string
	dateAdded                  time.Time
	dueDate                    time.Time
	knownRansomwareCampaignUse string
	notes                      string
	cwes                       []string
	createdAt                  time.Time
	updatedAt                  time.Time
}

// NewKEVEntry creates a new KEVEntry.
func NewKEVEntry(
	cveID, vendorProject, product, vulnerabilityName, shortDescription string,
	dateAdded, dueDate time.Time,
	ransomwareUse, notes string,
	cwes []string,
) *KEVEntry {
	now := time.Now().UTC()
	if cwes == nil {
		cwes = make([]string, 0)
	}
	return &KEVEntry{
		cveID:                      cveID,
		vendorProject:              vendorProject,
		product:                    product,
		vulnerabilityName:          vulnerabilityName,
		shortDescription:           shortDescription,
		dateAdded:                  dateAdded,
		dueDate:                    dueDate,
		knownRansomwareCampaignUse: ransomwareUse,
		notes:                      notes,
		cwes:                       cwes,
		createdAt:                  now,
		updatedAt:                  now,
	}
}

// ReconstituteKEVEntry recreates a KEVEntry from persistence.
func ReconstituteKEVEntry(
	cveID, vendorProject, product, vulnerabilityName, shortDescription string,
	dateAdded, dueDate time.Time,
	ransomwareUse, notes string,
	cwes []string,
	createdAt, updatedAt time.Time,
) *KEVEntry {
	if cwes == nil {
		cwes = make([]string, 0)
	}
	return &KEVEntry{
		cveID:                      cveID,
		vendorProject:              vendorProject,
		product:                    product,
		vulnerabilityName:          vulnerabilityName,
		shortDescription:           shortDescription,
		dateAdded:                  dateAdded,
		dueDate:                    dueDate,
		knownRansomwareCampaignUse: ransomwareUse,
		notes:                      notes,
		cwes:                       cwes,
		createdAt:                  createdAt,
		updatedAt:                  updatedAt,
	}
}

// Getters

// CVEID returns the CVE ID.
func (k *KEVEntry) CVEID() string { return k.cveID }

// VendorProject returns the vendor/project name.
func (k *KEVEntry) VendorProject() string { return k.vendorProject }

// Product returns the product name.
func (k *KEVEntry) Product() string { return k.product }

// VulnerabilityName returns the vulnerability name.
func (k *KEVEntry) VulnerabilityName() string { return k.vulnerabilityName }

// ShortDescription returns the short description.
func (k *KEVEntry) ShortDescription() string { return k.shortDescription }

// DateAdded returns the date added to KEV.
func (k *KEVEntry) DateAdded() time.Time { return k.dateAdded }

// DueDate returns the remediation due date.
func (k *KEVEntry) DueDate() time.Time { return k.dueDate }

// KnownRansomwareCampaignUse returns ransomware campaign usage info.
func (k *KEVEntry) KnownRansomwareCampaignUse() string { return k.knownRansomwareCampaignUse }

// Notes returns additional notes.
func (k *KEVEntry) Notes() string { return k.notes }

// CWEs returns the CWE IDs.
func (k *KEVEntry) CWEs() []string {
	cwes := make([]string, len(k.cwes))
	copy(cwes, k.cwes)
	return cwes
}

// CreatedAt returns the creation time.
func (k *KEVEntry) CreatedAt() time.Time { return k.createdAt }

// UpdatedAt returns the last update time.
func (k *KEVEntry) UpdatedAt() time.Time { return k.updatedAt }

// IsPastDue checks if the due date has passed.
func (k *KEVEntry) IsPastDue() bool {
	return !k.dueDate.IsZero() && time.Now().After(k.dueDate)
}

// DaysUntilDue returns days until due date (negative if past due).
func (k *KEVEntry) DaysUntilDue() int {
	if k.dueDate.IsZero() {
		return 0
	}
	return int(time.Until(k.dueDate).Hours() / 24)
}

// HasRansomwareUse returns true if known ransomware campaign use.
func (k *KEVEntry) HasRansomwareUse() bool {
	return k.knownRansomwareCampaignUse != "" && k.knownRansomwareCampaignUse != "Unknown"
}

// Update updates the KEV entry fields.
func (k *KEVEntry) Update(
	vendorProject, product, vulnerabilityName, shortDescription string,
	dueDate time.Time,
	ransomwareUse, notes string,
	cwes []string,
) {
	k.vendorProject = vendorProject
	k.product = product
	k.vulnerabilityName = vulnerabilityName
	k.shortDescription = shortDescription
	k.dueDate = dueDate
	k.knownRansomwareCampaignUse = ransomwareUse
	k.notes = notes
	if cwes != nil {
		k.cwes = make([]string, len(cwes))
		copy(k.cwes, cwes)
	}
	k.updatedAt = time.Now().UTC()
}

// SyncStatus represents the sync status for a threat intel source.
type SyncStatus struct {
	id                shared.ID
	sourceName        string
	lastSyncAt        *time.Time
	lastSyncStatus    SyncState
	lastSyncError     string
	recordsSynced     int
	syncDurationMs    int
	nextSyncAt        *time.Time
	syncIntervalHours int
	isEnabled         bool
	metadata          map[string]any
	createdAt         time.Time
	updatedAt         time.Time
}

// NewSyncStatus creates a new SyncStatus.
func NewSyncStatus(sourceName string, syncIntervalHours int) *SyncStatus {
	now := time.Now().UTC()
	return &SyncStatus{
		id:                shared.NewID(),
		sourceName:        sourceName,
		lastSyncStatus:    SyncStatePending,
		syncIntervalHours: syncIntervalHours,
		isEnabled:         true,
		metadata:          make(map[string]any),
		createdAt:         now,
		updatedAt:         now,
	}
}

// ReconstituteSyncStatus recreates a SyncStatus from persistence.
func ReconstituteSyncStatus(
	id shared.ID,
	sourceName string,
	lastSyncAt *time.Time,
	lastSyncStatus SyncState,
	lastSyncError string,
	recordsSynced, syncDurationMs int,
	nextSyncAt *time.Time,
	syncIntervalHours int,
	isEnabled bool,
	metadata map[string]any,
	createdAt, updatedAt time.Time,
) *SyncStatus {
	if metadata == nil {
		metadata = make(map[string]any)
	}
	return &SyncStatus{
		id:                id,
		sourceName:        sourceName,
		lastSyncAt:        lastSyncAt,
		lastSyncStatus:    lastSyncStatus,
		lastSyncError:     lastSyncError,
		recordsSynced:     recordsSynced,
		syncDurationMs:    syncDurationMs,
		nextSyncAt:        nextSyncAt,
		syncIntervalHours: syncIntervalHours,
		isEnabled:         isEnabled,
		metadata:          metadata,
		createdAt:         createdAt,
		updatedAt:         updatedAt,
	}
}

// Getters

// ID returns the sync status ID.
func (s *SyncStatus) ID() shared.ID { return s.id }

// SourceName returns the source name.
func (s *SyncStatus) SourceName() string { return s.sourceName }

// LastSyncAt returns the last sync time.
func (s *SyncStatus) LastSyncAt() *time.Time { return s.lastSyncAt }

// LastSyncStatus returns the last sync status.
func (s *SyncStatus) LastSyncStatus() SyncState { return s.lastSyncStatus }

// LastSyncError returns the last sync error.
func (s *SyncStatus) LastSyncError() string { return s.lastSyncError }

// RecordsSynced returns the number of records synced.
func (s *SyncStatus) RecordsSynced() int { return s.recordsSynced }

// SyncDurationMs returns the sync duration in milliseconds.
func (s *SyncStatus) SyncDurationMs() int { return s.syncDurationMs }

// NextSyncAt returns the next sync time.
func (s *SyncStatus) NextSyncAt() *time.Time { return s.nextSyncAt }

// SyncIntervalHours returns the sync interval in hours.
func (s *SyncStatus) SyncIntervalHours() int { return s.syncIntervalHours }

// IsEnabled returns whether sync is enabled.
func (s *SyncStatus) IsEnabled() bool { return s.isEnabled }

// Metadata returns a copy of the metadata.
func (s *SyncStatus) Metadata() map[string]any {
	m := make(map[string]any)
	for k, v := range s.metadata {
		m[k] = v
	}
	return m
}

// CreatedAt returns the creation time.
func (s *SyncStatus) CreatedAt() time.Time { return s.createdAt }

// UpdatedAt returns the last update time.
func (s *SyncStatus) UpdatedAt() time.Time { return s.updatedAt }

// Mutators

// MarkSyncStarted marks the sync as started.
func (s *SyncStatus) MarkSyncStarted() {
	now := time.Now().UTC()
	s.lastSyncAt = &now
	s.lastSyncStatus = SyncStateRunning
	s.lastSyncError = ""
	s.updatedAt = now
}

// MarkSyncSuccess marks the sync as successful.
func (s *SyncStatus) MarkSyncSuccess(recordsSynced int, durationMs int) {
	now := time.Now().UTC()
	s.lastSyncStatus = SyncStateSuccess
	s.recordsSynced = recordsSynced
	s.syncDurationMs = durationMs
	s.lastSyncError = ""

	// Calculate next sync time
	nextSync := now.Add(time.Duration(s.syncIntervalHours) * time.Hour)
	s.nextSyncAt = &nextSync
	s.updatedAt = now
}

// MarkSyncFailed marks the sync as failed.
func (s *SyncStatus) MarkSyncFailed(err string) {
	now := time.Now().UTC()
	s.lastSyncStatus = SyncStateFailed
	s.lastSyncError = err

	// Retry in 1 hour on failure
	nextSync := now.Add(1 * time.Hour)
	s.nextSyncAt = &nextSync
	s.updatedAt = now
}

// SetEnabled sets the enabled status.
func (s *SyncStatus) SetEnabled(enabled bool) {
	s.isEnabled = enabled
	s.updatedAt = time.Now().UTC()
}

// SetSyncInterval sets the sync interval.
func (s *SyncStatus) SetSyncInterval(hours int) {
	s.syncIntervalHours = hours
	s.updatedAt = time.Now().UTC()
}

// IsDueForSync checks if sync is due.
func (s *SyncStatus) IsDueForSync() bool {
	if !s.isEnabled {
		return false
	}
	if s.nextSyncAt == nil {
		return true
	}
	return time.Now().After(*s.nextSyncAt)
}
