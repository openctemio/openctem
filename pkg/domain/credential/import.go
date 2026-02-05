package credential

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// Default severity when not specified
const defaultSeverity = "medium"

// CredentialImport represents a single credential to import.
type CredentialImport struct {
	// Core fields (required)
	Identifier     string         `json:"identifier" validate:"required,max=500"`
	CredentialType CredentialType `json:"credential_type" validate:"required"`

	// Secret value (the actual leaked credential - password, API key, etc.)
	// This is sensitive data and should be encrypted at rest
	SecretValue string `json:"secret_value,omitempty"`

	// Source information (required)
	Source CredentialSource `json:"source" validate:"required"`

	// Severity and classification
	Severity       string         `json:"severity,omitempty"`       // If empty, auto-determined by credential type
	Classification Classification `json:"classification,omitempty"` // internal, external, partner, vendor

	// Deduplication key components
	DedupKey DedupKey `json:"dedup_key"`

	// Context information
	Context CredentialContext `json:"context"`

	// Status flags
	IsVerified bool `json:"is_verified,omitempty"`
	IsRevoked  bool `json:"is_revoked,omitempty"`

	// Tags and notes
	Tags  []string `json:"tags,omitempty"`
	Notes string   `json:"notes,omitempty"`
}

// CredentialSource contains source information.
type CredentialSource struct {
	Type         SourceType `json:"type" validate:"required"`
	Name         string     `json:"name,omitempty"`          // e.g., "HIBP", "SpyCloud", "GitGuardian"
	URL          string     `json:"url,omitempty"`           // Source URL if applicable
	DiscoveredAt *time.Time `json:"discovered_at,omitempty"` // When the credential was discovered
}

// DedupKey contains fields used for deduplication fingerprint.
type DedupKey struct {
	// For data breach credentials
	BreachName string `json:"breach_name,omitempty"`
	BreachDate string `json:"breach_date,omitempty"` // YYYY-MM-DD format

	// For code repository credentials
	Repository string `json:"repository,omitempty"`
	FilePath   string `json:"file_path,omitempty"`
	CommitHash string `json:"commit_hash,omitempty"`
	Branch     string `json:"branch,omitempty"`

	// For dark web / paste site credentials
	SourceURL string `json:"source_url,omitempty"`
	PasteID   string `json:"paste_id,omitempty"`
}

// CredentialContext contains additional context about the credential.
type CredentialContext struct {
	Username   string `json:"username,omitempty"`
	Email      string `json:"email,omitempty"`
	Domain     string `json:"domain,omitempty"`
	IPAddress  string `json:"ip_address,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	LineNumber int    `json:"line_number,omitempty"`

	// Additional arbitrary data
	Extra map[string]any `json:"extra,omitempty"`
}

// ImportOptions configures import behavior.
type ImportOptions struct {
	DedupStrategy        DedupStrategy `json:"dedup_strategy,omitempty"`         // How to handle duplicates
	ReactivateResolved   bool          `json:"reactivate_resolved,omitempty"`    // Reactivate resolved credentials if found again
	NotifyReactivated    bool          `json:"notify_reactivated,omitempty"`     // Send alert when credential is reactivated
	NotifyNewCritical    bool          `json:"notify_new_critical,omitempty"`    // Send alert on new critical findings
	AutoClassifySeverity bool          `json:"auto_classify_severity,omitempty"` // Auto-determine severity if not provided
}

// DefaultImportOptions returns default import options.
func DefaultImportOptions() ImportOptions {
	return ImportOptions{
		DedupStrategy:        DedupStrategyUpdateLastSeen,
		ReactivateResolved:   true,
		NotifyReactivated:    true,
		NotifyNewCritical:    true,
		AutoClassifySeverity: true,
	}
}

// ImportRequest represents a bulk import request.
type ImportRequest struct {
	Credentials []CredentialImport `json:"credentials" validate:"required,min=1,max=1000,dive"`
	Options     ImportOptions      `json:"options"`
	Metadata    ImportMetadata     `json:"metadata"`
}

// ImportMetadata contains metadata about the import.
type ImportMetadata struct {
	SourceTool  string    `json:"source_tool,omitempty"` // e.g., "hibp", "spycloud", "manual"
	ImportDate  time.Time `json:"import_date,omitempty"`
	BatchID     string    `json:"batch_id,omitempty"` // For tracking related imports
	Description string    `json:"description,omitempty"`
}

// ImportResult represents the result of an import operation.
type ImportResult struct {
	Imported    int                `json:"imported"`
	Updated     int                `json:"updated"`
	Reactivated int                `json:"reactivated"`
	Skipped     int                `json:"skipped"`
	Errors      []ImportError      `json:"errors,omitempty"`
	Details     []ImportItemResult `json:"details,omitempty"`
	Summary     ImportSummary      `json:"summary"`
}

// ImportError represents an error during import of a single credential.
type ImportError struct {
	Index      int    `json:"index"`
	Identifier string `json:"identifier"`
	Error      string `json:"error"`
}

// ImportItemResult represents the result of importing a single credential.
type ImportItemResult struct {
	Index      int    `json:"index"`
	Identifier string `json:"identifier"`
	Action     string `json:"action"` // imported, updated, reactivated, skipped, error
	Reason     string `json:"reason,omitempty"`
	ID         string `json:"id,omitempty"` // Exposure event ID if created/updated
}

// ImportSummary provides summary statistics.
type ImportSummary struct {
	TotalProcessed       int  `json:"total_processed"`
	SuccessCount         int  `json:"success_count"`
	ErrorCount           int  `json:"error_count"`
	CriticalCount        int  `json:"critical_count"`
	ReactivatedAlertSent bool `json:"reactivated_alert_sent"`
}

// CalculateFingerprint generates a SHA256 fingerprint for deduplication.
// The fingerprint is calculated based on the source type to ensure proper deduplication.
func (c *CredentialImport) CalculateFingerprint(tenantID string) string {
	// Normalize identifier (lowercase, trim)
	identifier := strings.ToLower(strings.TrimSpace(c.Identifier))

	components := map[string]any{
		"tenant_id":       tenantID,
		"identifier":      identifier,
		"credential_type": c.CredentialType.String(),
		"source_type":     c.Source.Type.String(),
	}

	// Add source-specific deduplication fields
	switch {
	case c.Source.Type.IsBreachSource():
		// For breach credentials: unique per breach
		if c.DedupKey.BreachName != "" {
			components["breach_name"] = strings.ToLower(strings.TrimSpace(c.DedupKey.BreachName))
		}
		if c.DedupKey.BreachDate != "" {
			components["breach_date"] = c.DedupKey.BreachDate
		}

	case c.Source.Type.IsCodeSource():
		// For code credentials: unique per file location
		if c.DedupKey.Repository != "" {
			components["repository"] = strings.ToLower(c.DedupKey.Repository)
		}
		if c.DedupKey.FilePath != "" {
			components["file_path"] = c.DedupKey.FilePath
		}
		if c.DedupKey.CommitHash != "" && len(c.DedupKey.CommitHash) >= 8 {
			components["commit_hash"] = c.DedupKey.CommitHash[:8]
		}

	default:
		// For dark web / paste site / other: unique per source URL or paste ID
		switch {
		case c.DedupKey.PasteID != "":
			components["paste_id"] = c.DedupKey.PasteID
		case c.DedupKey.SourceURL != "":
			components["source_url"] = strings.ToLower(c.DedupKey.SourceURL)
		case c.Source.URL != "":
			components["source_url"] = strings.ToLower(c.Source.URL)
		}
	}

	// Marshal to JSON and hash
	jsonData, _ := json.Marshal(components)
	hash := sha256.Sum256(jsonData)
	return hex.EncodeToString(hash[:])
}

// GetSeverity returns the severity, auto-determining if not set.
func (c *CredentialImport) GetSeverity(autoClassify bool) string {
	if c.Severity != "" {
		return c.Severity
	}
	if autoClassify {
		return c.CredentialType.DefaultSeverity()
	}
	return defaultSeverity
}

// GetClassification returns the classification or default.
func (c *CredentialImport) GetClassification() Classification {
	if c.Classification.IsValid() {
		return c.Classification
	}
	return ClassificationUnknown
}

// ToDetails converts credential import to exposure event details map.
func (c *CredentialImport) ToDetails() map[string]any {
	details := make(map[string]any)

	// Core credential info
	details["credential_type"] = c.CredentialType.String()
	details["classification"] = c.GetClassification().String()

	// Secret value (stored for later retrieval - should be encrypted at storage layer)
	if c.SecretValue != "" {
		details["secret_value"] = c.SecretValue
	}

	// Source info
	details["source_type"] = c.Source.Type.String()
	if c.Source.Name != "" {
		details["source_name"] = c.Source.Name
	}
	if c.Source.URL != "" {
		details["source_url"] = c.Source.URL
	}
	if c.Source.DiscoveredAt != nil {
		details["discovered_at"] = c.Source.DiscoveredAt.Format(time.RFC3339)
	}

	// Dedup key info
	if c.DedupKey.BreachName != "" {
		details["breach_name"] = c.DedupKey.BreachName
	}
	if c.DedupKey.BreachDate != "" {
		details["breach_date"] = c.DedupKey.BreachDate
	}
	if c.DedupKey.Repository != "" {
		details["repository"] = c.DedupKey.Repository
	}
	if c.DedupKey.FilePath != "" {
		details["file_path"] = c.DedupKey.FilePath
	}
	if c.DedupKey.CommitHash != "" {
		details["commit_hash"] = c.DedupKey.CommitHash
	}
	if c.DedupKey.Branch != "" {
		details["branch"] = c.DedupKey.Branch
	}
	if c.DedupKey.PasteID != "" {
		details["paste_id"] = c.DedupKey.PasteID
	}

	// Context info
	if c.Context.Username != "" {
		details["username"] = c.Context.Username
	}
	if c.Context.Email != "" {
		details["email"] = c.Context.Email
	}
	if c.Context.Domain != "" {
		details["domain"] = c.Context.Domain
	}
	if c.Context.IPAddress != "" {
		details["ip_address"] = c.Context.IPAddress
	}
	if c.Context.LineNumber > 0 {
		details["line_number"] = c.Context.LineNumber
	}

	// Status flags
	details["is_verified"] = c.IsVerified
	details["is_revoked"] = c.IsRevoked

	// Tags
	if len(c.Tags) > 0 {
		details["tags"] = c.Tags
	}

	// Extra context
	if len(c.Context.Extra) > 0 {
		for k, v := range c.Context.Extra {
			details["extra_"+k] = v
		}
	}

	return details
}

// GetSourceString returns formatted source string for exposure event.
func (c *CredentialImport) GetSourceString() string {
	if c.Source.Name != "" {
		return c.Source.Type.String() + " - " + c.Source.Name
	}
	return c.Source.Type.String()
}
