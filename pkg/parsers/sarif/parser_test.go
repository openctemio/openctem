package sarif

import (
	"strings"
	"testing"
)

// Sample SARIF data for testing.
var validSARIF = `{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "TestTool",
          "version": "1.0.0",
          "informationUri": "https://example.com",
          "rules": [
            {
              "id": "RULE001",
              "name": "test-rule",
              "shortDescription": {
                "text": "Test rule description"
              },
              "helpUri": "https://example.com/rules/RULE001"
            },
            {
              "id": "RULE002",
              "name": "another-rule",
              "shortDescription": {
                "text": "Another test rule"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "RULE001",
          "level": "error",
          "message": {
            "text": "This is an error"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "src/main.go"
                },
                "region": {
                  "startLine": 10,
                  "startColumn": 5
                }
              }
            }
          ]
        },
        {
          "ruleId": "RULE002",
          "level": "warning",
          "message": {
            "text": "This is a warning"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "src/utils.go"
                },
                "region": {
                  "startLine": 25,
                  "startColumn": 1
                }
              }
            }
          ]
        },
        {
          "ruleId": "RULE001",
          "level": "note",
          "message": {
            "text": "This is a note"
          }
        },
        {
          "ruleId": "RULE001",
          "kind": "pass",
          "level": "none",
          "message": {
            "text": "This check passed"
          }
        }
      ]
    }
  ]
}`

var suppressedResultSARIF = `{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "TestTool"
        }
      },
      "results": [
        {
          "ruleId": "RULE001",
          "level": "error",
          "message": {
            "text": "Suppressed error"
          },
          "suppressions": [
            {
              "kind": "inSource",
              "justification": "False positive"
            }
          ]
        },
        {
          "ruleId": "RULE002",
          "level": "warning",
          "message": {
            "text": "Active warning"
          }
        }
      ]
    }
  ]
}`

var invalidJSON = `{ invalid json }`

var unsupportedVersionSARIF = `{
  "version": "1.0.0",
  "runs": []
}`

var emptyRunsSARIF = `{
  "version": "2.1.0",
  "runs": []
}`

func TestNewParser(t *testing.T) {
	t.Run("with nil options uses defaults", func(t *testing.T) {
		p := NewParser(nil)
		if p == nil {
			t.Fatal("expected parser, got nil")
		}
		if p.opts == nil {
			t.Fatal("expected options, got nil")
		}
		if p.opts.StrictMode {
			t.Error("expected StrictMode to be false")
		}
	})

	t.Run("with custom options", func(t *testing.T) {
		opts := &Options{
			StrictMode: true,
			MinLevel:   LevelWarning,
			MaxResults: 10,
		}
		p := NewParser(opts)
		if !p.opts.StrictMode {
			t.Error("expected StrictMode to be true")
		}
		if p.opts.MinLevel != LevelWarning {
			t.Errorf("expected MinLevel %s, got %s", LevelWarning, p.opts.MinLevel)
		}
		if p.opts.MaxResults != 10 {
			t.Errorf("expected MaxResults 10, got %d", p.opts.MaxResults)
		}
	})
}

func TestParser_ParseBytes(t *testing.T) {
	t.Run("valid SARIF", func(t *testing.T) {
		p := NewParser(nil)
		log, err := p.ParseBytes([]byte(validSARIF))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if log.Version != "2.1.0" {
			t.Errorf("expected version 2.1.0, got %s", log.Version)
		}
		if len(log.Runs) != 1 {
			t.Fatalf("expected 1 run, got %d", len(log.Runs))
		}
		if log.Runs[0].Tool.Driver.Name != "TestTool" {
			t.Errorf("expected tool name TestTool, got %s", log.Runs[0].Tool.Driver.Name)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		p := NewParser(nil)
		_, err := p.ParseBytes([]byte(invalidJSON))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid SARIF format") {
			t.Errorf("expected invalid SARIF format error, got: %v", err)
		}
	})

	t.Run("unsupported version", func(t *testing.T) {
		p := NewParser(nil)
		_, err := p.ParseBytes([]byte(unsupportedVersionSARIF))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "unsupported SARIF version") {
			t.Errorf("expected unsupported version error, got: %v", err)
		}
	})

	t.Run("empty runs", func(t *testing.T) {
		p := NewParser(nil)
		_, err := p.ParseBytes([]byte(emptyRunsSARIF))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if err != ErrEmptyRuns {
			t.Errorf("expected ErrEmptyRuns, got: %v", err)
		}
	})
}

func TestParser_Parse(t *testing.T) {
	p := NewParser(nil)
	reader := strings.NewReader(validSARIF)
	log, err := p.Parse(reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %s", log.Version)
	}
}

func TestParser_FilterPassedResults(t *testing.T) {
	t.Run("exclude passed results by default", func(t *testing.T) {
		p := NewParser(nil)
		log, err := p.ParseBytes([]byte(validSARIF))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Default should exclude passed results
		for _, result := range log.Runs[0].Results {
			if result.Kind == KindPass {
				t.Error("expected passed results to be filtered out")
			}
		}
	})

	t.Run("include passed results when enabled", func(t *testing.T) {
		p := NewParser(&Options{IncludePassedResults: true})
		log, err := p.ParseBytes([]byte(validSARIF))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		hasPass := false
		for _, result := range log.Runs[0].Results {
			if result.Kind == KindPass {
				hasPass = true
				break
			}
		}
		if !hasPass {
			t.Error("expected passed results to be included")
		}
	})
}

func TestParser_FilterByMinLevel(t *testing.T) {
	t.Run("filter by warning level", func(t *testing.T) {
		p := NewParser(&Options{MinLevel: LevelWarning})
		log, err := p.ParseBytes([]byte(validSARIF))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, result := range log.Runs[0].Results {
			if result.Level == LevelNote || result.Level == LevelNone {
				t.Errorf("expected results below warning to be filtered, got level: %s", result.Level)
			}
		}
	})

	t.Run("filter by error level", func(t *testing.T) {
		p := NewParser(&Options{MinLevel: LevelError})
		log, err := p.ParseBytes([]byte(validSARIF))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, result := range log.Runs[0].Results {
			if result.Level != LevelError {
				t.Errorf("expected only error level results, got: %s", result.Level)
			}
		}
	})
}

func TestParser_FilterSuppressed(t *testing.T) {
	t.Run("exclude suppressed by default", func(t *testing.T) {
		p := NewParser(nil)
		log, err := p.ParseBytes([]byte(suppressedResultSARIF))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(log.Runs[0].Results) != 1 {
			t.Errorf("expected 1 result (suppressed filtered), got %d", len(log.Runs[0].Results))
		}
		if log.Runs[0].Results[0].RuleID != "RULE002" {
			t.Error("expected only non-suppressed result")
		}
	})

	t.Run("include suppressed when enabled", func(t *testing.T) {
		p := NewParser(&Options{IncludeSuppressed: true})
		log, err := p.ParseBytes([]byte(suppressedResultSARIF))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(log.Runs[0].Results) != 2 {
			t.Errorf("expected 2 results, got %d", len(log.Runs[0].Results))
		}
	})
}

func TestParser_MaxResults(t *testing.T) {
	p := NewParser(&Options{MaxResults: 2})
	log, err := p.ParseBytes([]byte(validSARIF))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(log.Runs[0].Results) > 2 {
		t.Errorf("expected max 2 results, got %d", len(log.Runs[0].Results))
	}
}

func TestParser_StrictMode(t *testing.T) {
	missingToolName := `{
		"version": "2.1.0",
		"runs": [
			{
				"tool": {
					"driver": {
						"name": ""
					}
				},
				"results": []
			}
		]
	}`

	t.Run("strict mode validates tool name", func(t *testing.T) {
		p := NewParser(&Options{StrictMode: true})
		_, err := p.ParseBytes([]byte(missingToolName))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "missing tool driver name") {
			t.Errorf("expected missing tool driver name error, got: %v", err)
		}
	})

	t.Run("non-strict mode allows missing tool name", func(t *testing.T) {
		p := NewParser(&Options{StrictMode: false})
		_, err := p.ParseBytes([]byte(missingToolName))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestGetAllResults(t *testing.T) {
	p := NewParser(&Options{IncludePassedResults: true})
	log, err := p.ParseBytes([]byte(validSARIF))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	results := GetAllResults(log)
	if len(results) != 4 {
		t.Errorf("expected 4 results, got %d", len(results))
	}
}

func TestGetResultsByLevel(t *testing.T) {
	p := NewParser(&Options{IncludePassedResults: true})
	log, err := p.ParseBytes([]byte(validSARIF))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	errors := GetResultsByLevel(log, LevelError)
	if len(errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(errors))
	}

	warnings := GetResultsByLevel(log, LevelWarning)
	if len(warnings) != 1 {
		t.Errorf("expected 1 warning, got %d", len(warnings))
	}
}

func TestGetResultsByRuleID(t *testing.T) {
	p := NewParser(&Options{IncludePassedResults: true})
	log, err := p.ParseBytes([]byte(validSARIF))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rule001Results := GetResultsByRuleID(log, "RULE001")
	if len(rule001Results) != 3 {
		t.Errorf("expected 3 results for RULE001, got %d", len(rule001Results))
	}

	rule002Results := GetResultsByRuleID(log, "RULE002")
	if len(rule002Results) != 1 {
		t.Errorf("expected 1 result for RULE002, got %d", len(rule002Results))
	}
}

func TestCountByLevel(t *testing.T) {
	p := NewParser(&Options{IncludePassedResults: true})
	log, err := p.ParseBytes([]byte(validSARIF))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	counts := CountByLevel(log)
	if counts[LevelError] != 1 {
		t.Errorf("expected 1 error, got %d", counts[LevelError])
	}
	if counts[LevelWarning] != 1 {
		t.Errorf("expected 1 warning, got %d", counts[LevelWarning])
	}
	if counts[LevelNote] != 1 {
		t.Errorf("expected 1 note, got %d", counts[LevelNote])
	}
}

func TestGetRuleDescriptor(t *testing.T) {
	p := NewParser(nil)
	log, err := p.ParseBytes([]byte(validSARIF))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	run := &log.Runs[0]
	result := &log.Runs[0].Results[0]

	rule := GetRuleDescriptor(run, result)
	if rule == nil {
		t.Fatal("expected rule descriptor, got nil")
	}
	if rule.ID != "RULE001" {
		t.Errorf("expected rule ID RULE001, got %s", rule.ID)
	}
}

func TestGetSummary(t *testing.T) {
	p := NewParser(&Options{IncludePassedResults: true})
	log, err := p.ParseBytes([]byte(validSARIF))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	summary := GetSummary(log)
	if summary.TotalResults != 4 {
		t.Errorf("expected 4 total results, got %d", summary.TotalResults)
	}
	if summary.RunCount != 1 {
		t.Errorf("expected 1 run, got %d", summary.RunCount)
	}
	if len(summary.Tools) != 1 || summary.Tools[0] != "TestTool" {
		t.Errorf("expected tools [TestTool], got %v", summary.Tools)
	}
	if summary.ByLevel[LevelError] != 1 {
		t.Errorf("expected 1 error in summary, got %d", summary.ByLevel[LevelError])
	}
}

func TestLevel_IsValid(t *testing.T) {
	tests := []struct {
		level Level
		valid bool
	}{
		{LevelNone, true},
		{LevelNote, true},
		{LevelWarning, true},
		{LevelError, true},
		{"", true},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			if got := tt.level.IsValid(); got != tt.valid {
				t.Errorf("Level(%q).IsValid() = %v, want %v", tt.level, got, tt.valid)
			}
		})
	}
}

func TestKind_IsValid(t *testing.T) {
	tests := []struct {
		kind  Kind
		valid bool
	}{
		{KindPass, true},
		{KindFail, true},
		{KindOpen, true},
		{KindReview, true},
		{KindNotApplicable, true},
		{KindInformational, true},
		{"", true},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			if got := tt.kind.IsValid(); got != tt.valid {
				t.Errorf("Kind(%q).IsValid() = %v, want %v", tt.kind, got, tt.valid)
			}
		})
	}
}
