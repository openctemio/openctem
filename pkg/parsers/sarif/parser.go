package sarif

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// Parser errors.
var (
	ErrInvalidSARIF       = errors.New("invalid SARIF format")
	ErrUnsupportedVersion = errors.New("unsupported SARIF version")
	ErrEmptyRuns          = errors.New("SARIF log contains no runs")
	ErrEmptyResults       = errors.New("run contains no results")
)

// SupportedVersions contains the supported SARIF versions.
var SupportedVersions = []string{"2.1.0"}

// Parser parses SARIF format files.
type Parser struct {
	opts *Options
}

// Options configures the parser behavior.
type Options struct {
	// StrictMode enables strict validation of SARIF documents.
	StrictMode bool

	// IncludePassedResults includes results with kind "pass" (default: false).
	IncludePassedResults bool

	// MinLevel filters results by minimum severity level.
	// Results with severity below this level are excluded.
	// Valid values: "", "none", "note", "warning", "error"
	MinLevel Level

	// MaxResults limits the number of results returned (0 = unlimited).
	MaxResults int

	// IncludeSuppressed includes suppressed results (default: false).
	IncludeSuppressed bool
}

// DefaultOptions returns the default parser options.
func DefaultOptions() *Options {
	return &Options{
		StrictMode:           false,
		IncludePassedResults: false,
		MinLevel:             "",
		MaxResults:           0,
		IncludeSuppressed:    false,
	}
}

// NewParser creates a new SARIF parser with the given options.
// If opts is nil, default options are used.
func NewParser(opts *Options) *Parser {
	if opts == nil {
		opts = DefaultOptions()
	}
	return &Parser{opts: opts}
}

// ParseFile parses a SARIF file from the given path.
func (p *Parser) ParseFile(path string) (*Log, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	return p.Parse(file)
}

// Parse parses SARIF content from a reader.
func (p *Parser) Parse(r io.Reader) (*Log, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read content: %w", err)
	}

	return p.ParseBytes(data)
}

// ParseBytes parses SARIF content from bytes.
func (p *Parser) ParseBytes(data []byte) (*Log, error) {
	var log Log
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSARIF, err)
	}

	if err := p.validate(&log); err != nil {
		return nil, err
	}

	if p.opts.StrictMode {
		if err := p.validateStrict(&log); err != nil {
			return nil, err
		}
	}

	p.applyFilters(&log)

	return &log, nil
}

// validate performs basic validation of the SARIF log.
func (p *Parser) validate(log *Log) error {
	if !p.isVersionSupported(log.Version) {
		return fmt.Errorf("%w: %s (supported: %v)", ErrUnsupportedVersion, log.Version, SupportedVersions)
	}

	if len(log.Runs) == 0 {
		return ErrEmptyRuns
	}

	return nil
}

// validateStrict performs strict validation of the SARIF log.
func (p *Parser) validateStrict(log *Log) error {
	for i, run := range log.Runs {
		if run.Tool.Driver.Name == "" {
			return fmt.Errorf("%w: run[%d] missing tool driver name", ErrInvalidSARIF, i)
		}

		for j, result := range run.Results {
			if result.Message.Text == "" && result.Message.ID == "" {
				return fmt.Errorf("%w: run[%d].results[%d] missing message", ErrInvalidSARIF, i, j)
			}

			if !result.Level.IsValid() {
				return fmt.Errorf("%w: run[%d].results[%d] invalid level: %s", ErrInvalidSARIF, i, j, result.Level)
			}

			if !result.Kind.IsValid() {
				return fmt.Errorf("%w: run[%d].results[%d] invalid kind: %s", ErrInvalidSARIF, i, j, result.Kind)
			}
		}
	}

	return nil
}

// applyFilters filters results based on parser options.
func (p *Parser) applyFilters(log *Log) {
	for i := range log.Runs {
		run := &log.Runs[i]
		filtered := make([]Result, 0, len(run.Results))

		for _, result := range run.Results {
			if p.shouldIncludeResult(&result) {
				filtered = append(filtered, result)
				if p.opts.MaxResults > 0 && len(filtered) >= p.opts.MaxResults {
					break
				}
			}
		}

		run.Results = filtered
	}
}

// shouldIncludeResult determines if a result should be included based on filters.
func (p *Parser) shouldIncludeResult(result *Result) bool {
	// Filter passed results
	if !p.opts.IncludePassedResults && result.Kind == KindPass {
		return false
	}

	// Filter suppressed results
	if !p.opts.IncludeSuppressed && len(result.Suppressions) > 0 {
		return false
	}

	// Filter by minimum level
	if p.opts.MinLevel != "" && !p.meetsMinLevel(result.Level) {
		return false
	}

	return true
}

// meetsMinLevel checks if the result level meets the minimum level requirement.
func (p *Parser) meetsMinLevel(level Level) bool {
	levelOrder := map[Level]int{
		"":           0,
		LevelNone:    0,
		LevelNote:    1,
		LevelWarning: 2,
		LevelError:   3,
	}

	resultLevel, ok := levelOrder[level]
	if !ok {
		resultLevel = 0
	}

	minLevel, ok := levelOrder[p.opts.MinLevel]
	if !ok {
		minLevel = 0
	}

	return resultLevel >= minLevel
}

// isVersionSupported checks if the SARIF version is supported.
func (p *Parser) isVersionSupported(version string) bool {
	for _, v := range SupportedVersions {
		if v == version {
			return true
		}
	}
	return false
}

// GetAllResults returns all results from all runs in the log.
func GetAllResults(log *Log) []Result {
	var results []Result
	for _, run := range log.Runs {
		results = append(results, run.Results...)
	}
	return results
}

// GetResultsByLevel returns results filtered by severity level.
func GetResultsByLevel(log *Log, level Level) []Result {
	var results []Result
	for _, run := range log.Runs {
		for _, result := range run.Results {
			if result.Level == level {
				results = append(results, result)
			}
		}
	}
	return results
}

// GetResultsByRuleID returns results filtered by rule ID.
func GetResultsByRuleID(log *Log, ruleID string) []Result {
	var results []Result
	for _, run := range log.Runs {
		for _, result := range run.Results {
			if result.RuleID == ruleID {
				results = append(results, result)
			}
		}
	}
	return results
}

// CountByLevel returns a map of result counts by severity level.
func CountByLevel(log *Log) map[Level]int {
	counts := make(map[Level]int)
	for _, run := range log.Runs {
		for _, result := range run.Results {
			counts[result.Level]++
		}
	}
	return counts
}

// GetRuleDescriptor finds the rule descriptor for a result.
func GetRuleDescriptor(run *Run, result *Result) *ReportingDescriptor {
	if result.RuleID == "" && result.RuleIndex == 0 && result.Rule == nil {
		return nil
	}

	rules := run.Tool.Driver.Rules

	// Try by rule index first
	if result.Rule != nil && result.Rule.Index >= 0 && result.Rule.Index < len(rules) {
		return &rules[result.Rule.Index]
	}

	if result.RuleIndex >= 0 && result.RuleIndex < len(rules) {
		return &rules[result.RuleIndex]
	}

	// Try by rule ID
	ruleID := result.RuleID
	if result.Rule != nil && result.Rule.ID != "" {
		ruleID = result.Rule.ID
	}

	for i := range rules {
		if rules[i].ID == ruleID {
			return &rules[i]
		}
	}

	return nil
}

// Summary contains summarized statistics from a SARIF log.
type Summary struct {
	TotalResults int           `json:"totalResults"`
	ByLevel      map[Level]int `json:"byLevel"`
	ByKind       map[Kind]int  `json:"byKind"`
	Tools        []string      `json:"tools"`
	RunCount     int           `json:"runCount"`
}

// GetSummary returns a summary of the SARIF log.
func GetSummary(log *Log) Summary {
	summary := Summary{
		ByLevel:  make(map[Level]int),
		ByKind:   make(map[Kind]int),
		Tools:    make([]string, 0, len(log.Runs)),
		RunCount: len(log.Runs),
	}

	for _, run := range log.Runs {
		summary.Tools = append(summary.Tools, run.Tool.Driver.Name)
		summary.TotalResults += len(run.Results)

		for _, result := range run.Results {
			summary.ByLevel[result.Level]++
			if result.Kind != "" {
				summary.ByKind[result.Kind]++
			}
		}
	}

	return summary
}
