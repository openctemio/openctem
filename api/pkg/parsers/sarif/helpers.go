package sarif

import (
	"path/filepath"
	"strconv"
	"strings"
)

// Finding represents a simplified finding extracted from SARIF results.
// This is useful for converting SARIF data to a normalized format.
type Finding struct {
	// ID is a unique identifier for this finding.
	ID string `json:"id,omitempty"`

	// RuleID is the rule that triggered this finding.
	RuleID string `json:"ruleId"`

	// RuleName is the human-readable name of the rule.
	RuleName string `json:"ruleName,omitempty"`

	// Level is the severity level (error, warning, note, none).
	Level Level `json:"level"`

	// Message is the finding message.
	Message string `json:"message"`

	// Description is a longer description from the rule.
	Description string `json:"description,omitempty"`

	// FilePath is the file where the finding was detected.
	FilePath string `json:"filePath,omitempty"`

	// StartLine is the starting line number (1-based).
	StartLine int `json:"startLine,omitempty"`

	// EndLine is the ending line number (1-based).
	EndLine int `json:"endLine,omitempty"`

	// StartColumn is the starting column number (1-based).
	StartColumn int `json:"startColumn,omitempty"`

	// EndColumn is the ending column number (1-based).
	EndColumn int `json:"endColumn,omitempty"`

	// Snippet is the code snippet where the finding was detected.
	Snippet string `json:"snippet,omitempty"`

	// ToolName is the name of the tool that produced this finding.
	ToolName string `json:"toolName"`

	// ToolVersion is the version of the tool.
	ToolVersion string `json:"toolVersion,omitempty"`

	// HelpURI is a URL for more information about the rule.
	HelpURI string `json:"helpUri,omitempty"`

	// Fingerprint is a unique fingerprint for deduplication.
	Fingerprint string `json:"fingerprint,omitempty"`

	// IsSuppressed indicates if this finding is suppressed.
	IsSuppressed bool `json:"isSuppressed,omitempty"`

	// Properties contains additional custom properties.
	Properties Properties `json:"properties,omitempty"`
}

// ExtractFindings converts SARIF results to a normalized Finding format.
func ExtractFindings(log *Log) []Finding {
	var findings []Finding

	for _, run := range log.Runs {
		toolName := run.Tool.Driver.Name
		toolVersion := run.Tool.Driver.Version

		for _, result := range run.Results {
			finding := Finding{
				ID:           result.GUID,
				RuleID:       result.RuleID,
				Level:        result.Level,
				Message:      result.Message.Text,
				ToolName:     toolName,
				ToolVersion:  toolVersion,
				IsSuppressed: len(result.Suppressions) > 0,
				Properties:   result.Properties,
			}

			// Get fingerprint
			if len(result.Fingerprints) > 0 {
				for _, fp := range result.Fingerprints {
					finding.Fingerprint = fp
					break
				}
			} else if len(result.PartialFingerprints) > 0 {
				for _, fp := range result.PartialFingerprints {
					finding.Fingerprint = fp
					break
				}
			}

			// Get rule details
			rule := GetRuleDescriptor(&run, &result)
			if rule != nil {
				finding.RuleName = rule.Name
				finding.HelpURI = rule.HelpURI
				if rule.ShortDescription != nil {
					finding.Description = rule.ShortDescription.Text
				} else if rule.FullDescription != nil {
					finding.Description = rule.FullDescription.Text
				}
			}

			// Get location details
			if len(result.Locations) > 0 {
				loc := result.Locations[0]
				if loc.PhysicalLocation != nil {
					if loc.PhysicalLocation.ArtifactLocation != nil {
						finding.FilePath = loc.PhysicalLocation.ArtifactLocation.URI
					}
					if loc.PhysicalLocation.Region != nil {
						region := loc.PhysicalLocation.Region
						finding.StartLine = region.StartLine
						finding.EndLine = region.EndLine
						finding.StartColumn = region.StartColumn
						finding.EndColumn = region.EndColumn
						if region.Snippet != nil {
							finding.Snippet = region.Snippet.Text
						}
					}
				}
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

// GroupFindingsByFile groups findings by file path.
func GroupFindingsByFile(findings []Finding) map[string][]Finding {
	grouped := make(map[string][]Finding)
	for _, f := range findings {
		path := f.FilePath
		if path == "" {
			path = "<unknown>"
		}
		grouped[path] = append(grouped[path], f)
	}
	return grouped
}

// GroupFindingsByRule groups findings by rule ID.
func GroupFindingsByRule(findings []Finding) map[string][]Finding {
	grouped := make(map[string][]Finding)
	for _, f := range findings {
		grouped[f.RuleID] = append(grouped[f.RuleID], f)
	}
	return grouped
}

// GroupFindingsByLevel groups findings by severity level.
func GroupFindingsByLevel(findings []Finding) map[Level][]Finding {
	grouped := make(map[Level][]Finding)
	for _, f := range findings {
		grouped[f.Level] = append(grouped[f.Level], f)
	}
	return grouped
}

// FilterFindingsByExtension filters findings by file extension.
func FilterFindingsByExtension(findings []Finding, extensions ...string) []Finding {
	extMap := make(map[string]bool)
	for _, ext := range extensions {
		ext = strings.TrimPrefix(ext, ".")
		extMap["."+ext] = true
	}

	var filtered []Finding
	for _, f := range findings {
		ext := filepath.Ext(f.FilePath)
		if extMap[ext] {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// FilterFindingsByPath filters findings by path prefix.
func FilterFindingsByPath(findings []Finding, pathPrefix string) []Finding {
	var filtered []Finding
	for _, f := range findings {
		if strings.HasPrefix(f.FilePath, pathPrefix) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// DeduplicateFindings removes duplicate findings based on fingerprint.
func DeduplicateFindings(findings []Finding) []Finding {
	seen := make(map[string]bool)
	var unique []Finding

	for _, f := range findings {
		key := f.Fingerprint
		if key == "" {
			// Generate a key from file, line, and rule
			key = f.FilePath + ":" + f.RuleID + ":" + f.Message
		}
		if !seen[key] {
			seen[key] = true
			unique = append(unique, f)
		}
	}

	return unique
}

// LevelToSeverity converts SARIF level to a numeric severity (0-10 scale).
func LevelToSeverity(level Level) float64 {
	switch level {
	case LevelError:
		return 8.0
	case LevelWarning:
		return 5.0
	case LevelNote:
		return 2.0
	case LevelNone:
		return 0.0
	default:
		return 5.0 // Default to medium
	}
}

// SeverityToLevel converts a numeric severity to SARIF level.
func SeverityToLevel(severity float64) Level {
	switch {
	case severity >= 7.0:
		return LevelError
	case severity >= 4.0:
		return LevelWarning
	case severity >= 1.0:
		return LevelNote
	default:
		return LevelNone
	}
}

// GetAffectedFiles returns a list of unique file paths from findings.
func GetAffectedFiles(findings []Finding) []string {
	seen := make(map[string]bool)
	var files []string

	for _, f := range findings {
		if f.FilePath != "" && !seen[f.FilePath] {
			seen[f.FilePath] = true
			files = append(files, f.FilePath)
		}
	}

	return files
}

// GetUniqueRules returns a list of unique rule IDs from findings.
func GetUniqueRules(findings []Finding) []string {
	seen := make(map[string]bool)
	var rules []string

	for _, f := range findings {
		if f.RuleID != "" && !seen[f.RuleID] {
			seen[f.RuleID] = true
			rules = append(rules, f.RuleID)
		}
	}

	return rules
}

// Stats contains statistics about findings.
type Stats struct {
	Total           int           `json:"total"`
	ByLevel         map[Level]int `json:"byLevel"`
	UniqueFiles     int           `json:"uniqueFiles"`
	UniqueRules     int           `json:"uniqueRules"`
	SuppressedCount int           `json:"suppressedCount"`
}

// CalculateStats calculates statistics from findings.
func CalculateStats(findings []Finding) Stats {
	stats := Stats{
		Total:   len(findings),
		ByLevel: make(map[Level]int),
	}

	files := make(map[string]bool)
	rules := make(map[string]bool)

	for _, f := range findings {
		stats.ByLevel[f.Level]++
		if f.FilePath != "" {
			files[f.FilePath] = true
		}
		if f.RuleID != "" {
			rules[f.RuleID] = true
		}
		if f.IsSuppressed {
			stats.SuppressedCount++
		}
	}

	stats.UniqueFiles = len(files)
	stats.UniqueRules = len(rules)

	return stats
}

// MergeLogs merges multiple SARIF logs into a single log.
func MergeLogs(logs ...*Log) *Log {
	if len(logs) == 0 {
		return &Log{Version: "2.1.0"}
	}

	merged := &Log{
		Version: logs[0].Version,
		Schema:  logs[0].Schema,
		Runs:    make([]Run, 0),
	}

	for _, log := range logs {
		if log != nil {
			merged.Runs = append(merged.Runs, log.Runs...)
		}
	}

	return merged
}

// GetResultLocation returns a formatted location string for a result.
// Format: "file.go:10:5" or "file.go:10-15:5" for multi-line results.
func GetResultLocation(result *Result) string {
	if len(result.Locations) == 0 {
		return ""
	}

	loc := result.Locations[0]
	if loc.PhysicalLocation == nil {
		return ""
	}

	var parts []string

	if loc.PhysicalLocation.ArtifactLocation != nil {
		parts = append(parts, loc.PhysicalLocation.ArtifactLocation.URI)
	}

	if loc.PhysicalLocation.Region != nil {
		region := loc.PhysicalLocation.Region
		if region.StartLine > 0 {
			lineStr := ""
			if region.EndLine > 0 && region.EndLine != region.StartLine {
				lineStr = formatRange(region.StartLine, region.EndLine)
			} else {
				lineStr = formatInt(region.StartLine)
			}
			parts = append(parts, lineStr)

			if region.StartColumn > 0 {
				parts = append(parts, formatInt(region.StartColumn))
			}
		}
	}

	return strings.Join(parts, ":")
}

func formatInt(n int) string {
	return strconv.Itoa(n)
}

func formatRange(start, end int) string {
	return strconv.Itoa(start) + "-" + strconv.Itoa(end)
}
