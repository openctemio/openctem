package ingest

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// ConvertCTISDataFlowToFindingDataFlows tests
// =============================================================================

func TestConvertCTISDataFlowToFindingDataFlows_NilDataFlow(t *testing.T) {
	findingID := shared.NewID()
	flows, locations, err := ConvertCTISDataFlowToFindingDataFlows(findingID, nil)
	assert.NoError(t, err)
	assert.Nil(t, flows)
	assert.Nil(t, locations)
}

func TestConvertCTISDataFlowToFindingDataFlows_EmptyDataFlow(t *testing.T) {
	findingID := shared.NewID()
	df := &ctis.DataFlow{}

	flows, locations, err := ConvertCTISDataFlowToFindingDataFlows(findingID, df)
	require.NoError(t, err)
	require.Len(t, flows, 1)
	assert.Equal(t, findingID, flows[0].FindingID())
	assert.Equal(t, 0, flows[0].FlowIndex())
	assert.Equal(t, "essential", flows[0].Importance())
	assert.Empty(t, locations)
}

func TestConvertCTISDataFlowToFindingDataFlows_WithSummary(t *testing.T) {
	findingID := shared.NewID()
	df := &ctis.DataFlow{
		Summary: "User input flows to SQL query",
	}

	flows, _, err := ConvertCTISDataFlowToFindingDataFlows(findingID, df)
	require.NoError(t, err)
	require.Len(t, flows, 1)
	assert.Equal(t, "User input flows to SQL query", flows[0].Message())
}

func TestConvertCTISDataFlowToFindingDataFlows_OnlySources(t *testing.T) {
	findingID := shared.NewID()
	df := &ctis.DataFlow{
		Sources: []ctis.DataFlowLocation{
			{Path: "src/input.go", Line: 10, Label: "userInput"},
			{Path: "src/input.go", Line: 20, Label: "queryParam"},
		},
	}

	flows, locations, err := ConvertCTISDataFlowToFindingDataFlows(findingID, df)
	require.NoError(t, err)
	require.Len(t, flows, 1)
	require.Len(t, locations, 2)

	// Both should be source type
	assert.Equal(t, vulnerability.LocationTypeSource, locations[0].LocationType())
	assert.Equal(t, vulnerability.LocationTypeSource, locations[1].LocationType())

	// Step indices should be sequential
	assert.Equal(t, 0, locations[0].StepIndex())
	assert.Equal(t, 1, locations[1].StepIndex())
}

func TestConvertCTISDataFlowToFindingDataFlows_OnlySinks(t *testing.T) {
	findingID := shared.NewID()
	df := &ctis.DataFlow{
		Sinks: []ctis.DataFlowLocation{
			{Path: "src/db.go", Line: 42, Label: "sqlExec"},
		},
	}

	flows, locations, err := ConvertCTISDataFlowToFindingDataFlows(findingID, df)
	require.NoError(t, err)
	require.Len(t, flows, 1)
	require.Len(t, locations, 1)
	assert.Equal(t, vulnerability.LocationTypeSink, locations[0].LocationType())
	assert.Equal(t, 0, locations[0].StepIndex())
}

func TestConvertCTISDataFlowToFindingDataFlows_FullFlow(t *testing.T) {
	findingID := shared.NewID()
	df := &ctis.DataFlow{
		Summary: "SQL Injection via user input",
		Sources: []ctis.DataFlowLocation{
			{Path: "src/handler.go", Line: 10, Label: "req.Body"},
		},
		Intermediates: []ctis.DataFlowLocation{
			{Path: "src/service.go", Line: 25, Label: "query"},
			{Path: "src/repo.go", Line: 30, Label: "stmt"},
		},
		Sinks: []ctis.DataFlowLocation{
			{Path: "src/db.go", Line: 42, Label: "db.Exec"},
		},
	}

	flows, locations, err := ConvertCTISDataFlowToFindingDataFlows(findingID, df)
	require.NoError(t, err)
	require.Len(t, flows, 1)
	require.Len(t, locations, 4)

	// Verify types
	assert.Equal(t, vulnerability.LocationTypeSource, locations[0].LocationType())
	assert.Equal(t, vulnerability.LocationTypeIntermediate, locations[1].LocationType())
	assert.Equal(t, vulnerability.LocationTypeIntermediate, locations[2].LocationType())
	assert.Equal(t, vulnerability.LocationTypeSink, locations[3].LocationType())

	// Verify sequential step indices
	for i, loc := range locations {
		assert.Equal(t, i, loc.StepIndex(), "step index mismatch at position %d", i)
	}
}

func TestConvertCTISDataFlowToFindingDataFlows_AllLocationTypes(t *testing.T) {
	findingID := shared.NewID()
	df := &ctis.DataFlow{
		Sources: []ctis.DataFlowLocation{
			{Path: "input.go", Line: 1, Label: "source"},
		},
		Intermediates: []ctis.DataFlowLocation{
			{Path: "process.go", Line: 10, Label: "intermediate"},
		},
		Sanitizers: []ctis.DataFlowLocation{
			{Path: "sanitize.go", Line: 20, Label: "sanitizer"},
		},
		Sinks: []ctis.DataFlowLocation{
			{Path: "output.go", Line: 30, Label: "sink"},
		},
	}

	flows, locations, err := ConvertCTISDataFlowToFindingDataFlows(findingID, df)
	require.NoError(t, err)
	require.Len(t, flows, 1)
	require.Len(t, locations, 4)

	// Order: sources, intermediates, sanitizers, sinks
	assert.Equal(t, vulnerability.LocationTypeSource, locations[0].LocationType())
	assert.Equal(t, vulnerability.LocationTypeIntermediate, locations[1].LocationType())
	assert.Equal(t, vulnerability.LocationTypeSanitizer, locations[2].LocationType())
	assert.Equal(t, vulnerability.LocationTypeSink, locations[3].LocationType())

	// Step indices must be sequential across all location types
	assert.Equal(t, 0, locations[0].StepIndex())
	assert.Equal(t, 1, locations[1].StepIndex())
	assert.Equal(t, 2, locations[2].StepIndex())
	assert.Equal(t, 3, locations[3].StepIndex())
}

func TestConvertCTISDataFlowToFindingDataFlows_StepIndicesSequentialAcrossTypes(t *testing.T) {
	findingID := shared.NewID()
	df := &ctis.DataFlow{
		Sources: []ctis.DataFlowLocation{
			{Path: "a.go", Line: 1},
			{Path: "b.go", Line: 2},
		},
		Intermediates: []ctis.DataFlowLocation{
			{Path: "c.go", Line: 3},
		},
		Sanitizers: []ctis.DataFlowLocation{
			{Path: "d.go", Line: 4},
			{Path: "e.go", Line: 5},
		},
		Sinks: []ctis.DataFlowLocation{
			{Path: "f.go", Line: 6},
		},
	}

	_, locations, err := ConvertCTISDataFlowToFindingDataFlows(findingID, df)
	require.NoError(t, err)
	require.Len(t, locations, 6)

	// Step indices: 0, 1, 2, 3, 4, 5
	for i, loc := range locations {
		assert.Equal(t, i, loc.StepIndex(), "step index at position %d", i)
	}
}

func TestConvertCTISDataFlowToFindingDataFlows_PhysicalLocationFields(t *testing.T) {
	findingID := shared.NewID()
	df := &ctis.DataFlow{
		Sources: []ctis.DataFlowLocation{
			{
				Path:      "src/main.go",
				Line:      10,
				EndLine:   12,
				Column:    5,
				EndColumn: 30,
				Content:   "query := fmt.Sprintf(\"SELECT * FROM users WHERE id = %s\", input)",
			},
		},
	}

	_, locations, err := ConvertCTISDataFlowToFindingDataFlows(findingID, df)
	require.NoError(t, err)
	require.Len(t, locations, 1)

	loc := locations[0]
	assert.Equal(t, "src/main.go", loc.FilePath())
	assert.Equal(t, 10, loc.StartLine())
	assert.Equal(t, 12, loc.EndLine())
	assert.Equal(t, 5, loc.StartColumn())
	assert.Equal(t, 30, loc.EndColumn())
	assert.Equal(t, "query := fmt.Sprintf(\"SELECT * FROM users WHERE id = %s\", input)", loc.Snippet())
}

func TestConvertCTISDataFlowToFindingDataFlows_LogicalLocationFields(t *testing.T) {
	findingID := shared.NewID()
	df := &ctis.DataFlow{
		Sinks: []ctis.DataFlowLocation{
			{
				Path:     "src/repo.go",
				Line:     42,
				Function: "ExecuteQuery",
				Class:    "UserRepository",
				Module:   "internal/repo",
			},
		},
	}

	_, locations, err := ConvertCTISDataFlowToFindingDataFlows(findingID, df)
	require.NoError(t, err)
	require.Len(t, locations, 1)

	loc := locations[0]
	assert.Equal(t, "ExecuteQuery", loc.FunctionName())
	assert.Equal(t, "UserRepository", loc.ClassName())
	assert.Equal(t, "internal/repo", loc.ModuleName())
	// FQN is passed as empty string in the converter
	assert.Equal(t, "", loc.FullyQualifiedName())
}

func TestConvertCTISDataFlowToFindingDataFlows_ContextFields(t *testing.T) {
	findingID := shared.NewID()
	df := &ctis.DataFlow{
		Sources: []ctis.DataFlowLocation{
			{
				Path:  "src/handler.go",
				Line:  10,
				Label: "userInput",
				Notes: "User-controlled input from HTTP request body",
			},
		},
	}

	_, locations, err := ConvertCTISDataFlowToFindingDataFlows(findingID, df)
	require.NoError(t, err)
	require.Len(t, locations, 1)

	loc := locations[0]
	assert.Equal(t, "userInput", loc.Label())
	assert.Equal(t, "User-controlled input from HTTP request body", loc.Message())
	assert.Equal(t, 0, loc.NestingLevel())
	assert.Equal(t, "essential", loc.Importance())
}

func TestConvertCTISDataFlowToFindingDataFlows_LocationsShareFlowID(t *testing.T) {
	findingID := shared.NewID()
	df := &ctis.DataFlow{
		Sources: []ctis.DataFlowLocation{
			{Path: "a.go", Line: 1},
		},
		Sinks: []ctis.DataFlowLocation{
			{Path: "b.go", Line: 2},
		},
	}

	flows, locations, err := ConvertCTISDataFlowToFindingDataFlows(findingID, df)
	require.NoError(t, err)
	require.Len(t, flows, 1)
	require.Len(t, locations, 2)

	// All locations should reference the same flow ID
	flowID := flows[0].ID()
	assert.False(t, flowID.IsZero())
	assert.Equal(t, flowID, locations[0].DataFlowID())
	assert.Equal(t, flowID, locations[1].DataFlowID())
}

func TestConvertCTISDataFlowToFindingDataFlows_EachLocationGetsUniqueID(t *testing.T) {
	findingID := shared.NewID()
	df := &ctis.DataFlow{
		Sources: []ctis.DataFlowLocation{
			{Path: "a.go", Line: 1},
		},
		Intermediates: []ctis.DataFlowLocation{
			{Path: "b.go", Line: 2},
		},
		Sinks: []ctis.DataFlowLocation{
			{Path: "c.go", Line: 3},
		},
	}

	_, locations, err := ConvertCTISDataFlowToFindingDataFlows(findingID, df)
	require.NoError(t, err)
	require.Len(t, locations, 3)

	ids := make(map[string]bool)
	for _, loc := range locations {
		idStr := loc.ID().String()
		assert.False(t, ids[idStr], "duplicate location ID found: %s", idStr)
		ids[idStr] = true
	}
}

// =============================================================================
// ConvertSARIFCodeFlowsToCTISDataFlows tests
// =============================================================================

func TestConvertSARIFCodeFlowsToCTISDataFlows_NilInput(t *testing.T) {
	result := ConvertSARIFCodeFlowsToCTISDataFlows(nil)
	assert.Nil(t, result)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_NonSliceInput(t *testing.T) {
	result := ConvertSARIFCodeFlowsToCTISDataFlows("not a slice")
	assert.Nil(t, result)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_NonSliceInputMap(t *testing.T) {
	result := ConvertSARIFCodeFlowsToCTISDataFlows(map[string]any{"key": "value"})
	assert.Nil(t, result)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_NonSliceInputInt(t *testing.T) {
	result := ConvertSARIFCodeFlowsToCTISDataFlows(42)
	assert.Nil(t, result)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_EmptySlice(t *testing.T) {
	result := ConvertSARIFCodeFlowsToCTISDataFlows([]any{})
	assert.NotNil(t, result)
	assert.Empty(t, result)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_CodeFlowNotMap(t *testing.T) {
	// codeFlow entries that are not map[string]any should be skipped
	result := ConvertSARIFCodeFlowsToCTISDataFlows([]any{"not a map", 123})
	assert.Empty(t, result)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_NoThreadFlows(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			// no threadFlows key
		},
	}
	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	assert.Empty(t, result)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_EmptyThreadFlows(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{},
		},
	}
	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	assert.Empty(t, result)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_ThreadFlowNotMap(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{"not a map"},
		},
	}
	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	assert.Empty(t, result)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_NoLocations(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					// no locations key
				},
			},
		},
	}
	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	assert.Empty(t, result)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_EmptyLocations(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{},
				},
			},
		},
	}
	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	assert.Empty(t, result)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_SingleLocation(t *testing.T) {
	// Single location: first (and only) item becomes source; no sink because i==0 and i==len-1
	// In the switch: i==0 wins, so it becomes source
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"artifactLocation": map[string]any{
										"uri": "src/main.go",
									},
									"region": map[string]any{
										"startLine": float64(10),
									},
								},
							},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)

	df := result[0]
	assert.True(t, df.Tainted)
	// Single location: i==0 so it's a source (switch case i==0 takes precedence)
	require.Len(t, df.Sources, 1)
	assert.Empty(t, df.Sinks)
	assert.Empty(t, df.Intermediates)
	assert.Equal(t, "src/main.go", df.Sources[0].Path)
	assert.Equal(t, 10, df.Sources[0].Line)
	assert.Equal(t, ctis.DataFlowLocationSource, df.Sources[0].Type)
	assert.Equal(t, "tainted", df.Sources[0].TaintState)
	assert.Equal(t, 0, df.Sources[0].Index)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_TwoLocations(t *testing.T) {
	// Two locations: first is source, second (last) is sink
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"artifactLocation": map[string]any{
										"uri": "src/input.go",
									},
									"region": map[string]any{
										"startLine": float64(5),
									},
								},
							},
						},
						map[string]any{
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"artifactLocation": map[string]any{
										"uri": "src/db.go",
									},
									"region": map[string]any{
										"startLine": float64(42),
									},
								},
							},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)

	df := result[0]
	require.Len(t, df.Sources, 1)
	require.Len(t, df.Sinks, 1)
	assert.Empty(t, df.Intermediates)

	assert.Equal(t, "src/input.go", df.Sources[0].Path)
	assert.Equal(t, 5, df.Sources[0].Line)
	assert.Equal(t, ctis.DataFlowLocationSource, df.Sources[0].Type)

	assert.Equal(t, "src/db.go", df.Sinks[0].Path)
	assert.Equal(t, 42, df.Sinks[0].Line)
	assert.Equal(t, ctis.DataFlowLocationSink, df.Sinks[0].Type)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_ThreeLocations(t *testing.T) {
	// Three locations: first is source, middle is intermediate (propagator), last is sink
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"artifactLocation": map[string]any{"uri": "a.go"},
									"region":           map[string]any{"startLine": float64(1)},
								},
							},
						},
						map[string]any{
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"artifactLocation": map[string]any{"uri": "b.go"},
									"region":           map[string]any{"startLine": float64(2)},
								},
							},
						},
						map[string]any{
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"artifactLocation": map[string]any{"uri": "c.go"},
									"region":           map[string]any{"startLine": float64(3)},
								},
							},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)

	df := result[0]
	require.Len(t, df.Sources, 1)
	require.Len(t, df.Intermediates, 1)
	require.Len(t, df.Sinks, 1)

	assert.Equal(t, ctis.DataFlowLocationSource, df.Sources[0].Type)
	assert.Equal(t, 0, df.Sources[0].Index)

	assert.Equal(t, ctis.DataFlowLocationPropagator, df.Intermediates[0].Type)
	assert.Equal(t, 1, df.Intermediates[0].Index)

	assert.Equal(t, ctis.DataFlowLocationSink, df.Sinks[0].Type)
	assert.Equal(t, 2, df.Sinks[0].Index)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_PhysicalLocationExtraction(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"artifactLocation": map[string]any{
										"uri": "src/handler.go",
									},
									"region": map[string]any{
										"startLine":   float64(10),
										"endLine":     float64(12),
										"startColumn": float64(5),
										"endColumn":   float64(45),
										"snippet": map[string]any{
											"text": "query := fmt.Sprintf(sql, input)",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)
	require.Len(t, result[0].Sources, 1)

	src := result[0].Sources[0]
	assert.Equal(t, "src/handler.go", src.Path)
	assert.Equal(t, 10, src.Line)
	assert.Equal(t, 12, src.EndLine)
	assert.Equal(t, 5, src.Column)
	assert.Equal(t, 45, src.EndColumn)
	assert.Equal(t, "query := fmt.Sprintf(sql, input)", src.Content)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_LogicalLocationExtraction(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{
								"logicalLocations": []any{
									map[string]any{
										"name": "processInput",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)
	require.Len(t, result[0].Sources, 1)

	src := result[0].Sources[0]
	assert.Equal(t, "processInput", src.Function)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_LogicalLocationFQNOverridesName(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{
								"logicalLocations": []any{
									map[string]any{
										"name":               "processInput",
										"fullyQualifiedName": "com.example.Service.processInput",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)
	require.Len(t, result[0].Sources, 1)

	// fullyQualifiedName overrides name in the Function field
	src := result[0].Sources[0]
	assert.Equal(t, "com.example.Service.processInput", src.Function)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_MessageExtraction(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{
								"message": map[string]any{
									"text": "User input received here",
								},
							},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)
	require.Len(t, result[0].Sources, 1)

	src := result[0].Sources[0]
	assert.Equal(t, "User input received here", src.Notes)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_ImportancePrefixInNotes(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"importance": "essential",
							"location": map[string]any{
								"message": map[string]any{
									"text": "Data flows through here",
								},
							},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)
	require.Len(t, result[0].Sources, 1)

	src := result[0].Sources[0]
	assert.Equal(t, "essential: Data flows through here", src.Notes)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_ImportanceWithoutMessage(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"importance": "important",
							"location":   map[string]any{},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)
	require.Len(t, result[0].Sources, 1)

	src := result[0].Sources[0]
	// importance prefix + ": " + empty notes
	assert.Equal(t, "important: ", src.Notes)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_MultipleCodeFlows(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"artifactLocation": map[string]any{"uri": "flow1_source.go"},
								},
							},
						},
						map[string]any{
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"artifactLocation": map[string]any{"uri": "flow1_sink.go"},
								},
							},
						},
					},
				},
			},
		},
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"artifactLocation": map[string]any{"uri": "flow2_source.go"},
								},
							},
						},
						map[string]any{
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"artifactLocation": map[string]any{"uri": "flow2_sink.go"},
								},
							},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 2)

	// First flow
	require.Len(t, result[0].Sources, 1)
	require.Len(t, result[0].Sinks, 1)
	assert.Equal(t, "flow1_source.go", result[0].Sources[0].Path)
	assert.Equal(t, "flow1_sink.go", result[0].Sinks[0].Path)

	// Second flow
	require.Len(t, result[1].Sources, 1)
	require.Len(t, result[1].Sinks, 1)
	assert.Equal(t, "flow2_source.go", result[1].Sources[0].Path)
	assert.Equal(t, "flow2_sink.go", result[1].Sinks[0].Path)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_TaintedDefaultTrue(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)
	assert.True(t, result[0].Tainted)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_LocationNotMap(t *testing.T) {
	// Thread flow locations that are not map[string]any should be skipped
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						"not a map",
						42,
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	// The flow has no valid locations -> still a DataFlow (non-nil) since we checked len(locations)>0
	// Actually locations were originally 2 items, but neither was map[string]any, so they were skipped.
	// The result DataFlow will have no sources/sinks but was still created.
	// Wait - locations is checked via ok && len check, but locations was type-asserted from threadFlow["locations"].
	// The []any had 2 elements that were skipped in the for loop.
	// The df is created and returned because it's non-nil.
	require.Len(t, result, 1)
	assert.Empty(t, result[0].Sources)
	assert.Empty(t, result[0].Sinks)
	assert.Empty(t, result[0].Intermediates)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_NoLocationObject(t *testing.T) {
	// threadFlowLocation without a "location" key
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"nestingLevel": float64(0),
							// no "location" key
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)
	// The location was processed but extractSARIFLocation returns empty loc
	require.Len(t, result[0].Sources, 1)
	assert.Equal(t, "", result[0].Sources[0].Path)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_PartialPhysicalLocation(t *testing.T) {
	// physicalLocation with only some fields
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"artifactLocation": map[string]any{
										"uri": "partial.go",
									},
									// no region
								},
							},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)
	require.Len(t, result[0].Sources, 1)

	src := result[0].Sources[0]
	assert.Equal(t, "partial.go", src.Path)
	assert.Equal(t, 0, src.Line)
	assert.Equal(t, 0, src.EndLine)
	assert.Equal(t, 0, src.Column)
	assert.Equal(t, 0, src.EndColumn)
	assert.Equal(t, "", src.Content)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_PartialRegion(t *testing.T) {
	// Region with only startLine
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"region": map[string]any{
										"startLine": float64(42),
									},
								},
							},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)
	require.Len(t, result[0].Sources, 1)

	src := result[0].Sources[0]
	assert.Equal(t, 42, src.Line)
	assert.Equal(t, 0, src.EndLine)
	assert.Equal(t, 0, src.Column)
	assert.Equal(t, 0, src.EndColumn)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_SnippetExtraction(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"region": map[string]any{
										"snippet": map[string]any{
											"text": "db.Query(userInput)",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)
	require.Len(t, result[0].Sources, 1)
	assert.Equal(t, "db.Query(userInput)", result[0].Sources[0].Content)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_EmptyLogicalLocations(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{
								"logicalLocations": []any{},
							},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)
	require.Len(t, result[0].Sources, 1)
	assert.Equal(t, "", result[0].Sources[0].Function)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_LogicalLocationNotMap(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{
								"logicalLocations": []any{
									"not a map",
								},
							},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)
	require.Len(t, result[0].Sources, 1)
	assert.Equal(t, "", result[0].Sources[0].Function)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_SourceTaintState(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{},
						},
						map[string]any{
							"location": map[string]any{},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)
	require.Len(t, result[0].Sources, 1)
	assert.Equal(t, "tainted", result[0].Sources[0].TaintState)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_ManyIntermediates(t *testing.T) {
	// 5 locations: first=source, last=sink, middle 3=intermediates
	locs := make([]any, 5)
	for i := 0; i < 5; i++ {
		locs[i] = map[string]any{
			"location": map[string]any{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]any{
						"uri": "step" + string(rune('0'+i)) + ".go",
					},
					"region": map[string]any{
						"startLine": float64(i + 1),
					},
				},
			},
		}
	}

	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": locs,
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)

	df := result[0]
	require.Len(t, df.Sources, 1)
	require.Len(t, df.Intermediates, 3)
	require.Len(t, df.Sinks, 1)

	assert.Equal(t, 0, df.Sources[0].Index)
	assert.Equal(t, 1, df.Intermediates[0].Index)
	assert.Equal(t, 2, df.Intermediates[1].Index)
	assert.Equal(t, 3, df.Intermediates[2].Index)
	assert.Equal(t, 4, df.Sinks[0].Index)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_MixedValidAndInvalidCodeFlows(t *testing.T) {
	codeFlows := []any{
		// Valid codeFlow
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"artifactLocation": map[string]any{"uri": "valid.go"},
								},
							},
						},
					},
				},
			},
		},
		// Invalid codeFlow (no threadFlows)
		map[string]any{},
		// Another valid codeFlow
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"artifactLocation": map[string]any{"uri": "also_valid.go"},
								},
							},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 2)
	assert.Equal(t, "valid.go", result[0].Sources[0].Path)
	assert.Equal(t, "also_valid.go", result[1].Sources[0].Path)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_CompleteRealWorldSARIF(t *testing.T) {
	// Simulates a realistic SARIF codeFlow for a SQL injection finding
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						// Source: user input
						map[string]any{
							"importance": "essential",
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"artifactLocation": map[string]any{
										"uri": "src/handlers/user_handler.go",
									},
									"region": map[string]any{
										"startLine":   float64(42),
										"endLine":     float64(42),
										"startColumn": float64(12),
										"endColumn":   float64(35),
										"snippet": map[string]any{
											"text": "userID := r.URL.Query().Get(\"id\")",
										},
									},
								},
								"logicalLocations": []any{
									map[string]any{
										"name":               "GetUser",
										"fullyQualifiedName": "handlers.UserHandler.GetUser",
									},
								},
								"message": map[string]any{
									"text": "User input from query parameter",
								},
							},
						},
						// Intermediate: string concatenation
						map[string]any{
							"importance": "important",
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"artifactLocation": map[string]any{
										"uri": "src/services/user_service.go",
									},
									"region": map[string]any{
										"startLine":   float64(78),
										"endLine":     float64(78),
										"startColumn": float64(10),
										"endColumn":   float64(55),
										"snippet": map[string]any{
											"text": "query := \"SELECT * FROM users WHERE id = \" + userID",
										},
									},
								},
								"logicalLocations": []any{
									map[string]any{
										"name": "FindUser",
									},
								},
								"message": map[string]any{
									"text": "Tainted data concatenated into SQL query",
								},
							},
						},
						// Sink: SQL execution
						map[string]any{
							"importance": "essential",
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"artifactLocation": map[string]any{
										"uri": "src/repositories/user_repo.go",
									},
									"region": map[string]any{
										"startLine":   float64(25),
										"endLine":     float64(25),
										"startColumn": float64(2),
										"endColumn":   float64(30),
										"snippet": map[string]any{
											"text": "db.Query(query)",
										},
									},
								},
								"logicalLocations": []any{
									map[string]any{
										"name":               "Query",
										"fullyQualifiedName": "repositories.UserRepo.Query",
									},
								},
								"message": map[string]any{
									"text": "SQL query executed with tainted data",
								},
							},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)

	df := result[0]
	assert.True(t, df.Tainted)

	// Source
	require.Len(t, df.Sources, 1)
	src := df.Sources[0]
	assert.Equal(t, "src/handlers/user_handler.go", src.Path)
	assert.Equal(t, 42, src.Line)
	assert.Equal(t, 42, src.EndLine)
	assert.Equal(t, 12, src.Column)
	assert.Equal(t, 35, src.EndColumn)
	assert.Equal(t, "userID := r.URL.Query().Get(\"id\")", src.Content)
	assert.Equal(t, "handlers.UserHandler.GetUser", src.Function) // FQN overrides name
	assert.Equal(t, ctis.DataFlowLocationSource, src.Type)
	assert.Equal(t, "tainted", src.TaintState)
	assert.Equal(t, 0, src.Index)
	assert.Equal(t, "essential: User input from query parameter", src.Notes)

	// Intermediate
	require.Len(t, df.Intermediates, 1)
	inter := df.Intermediates[0]
	assert.Equal(t, "src/services/user_service.go", inter.Path)
	assert.Equal(t, 78, inter.Line)
	assert.Equal(t, "FindUser", inter.Function)
	assert.Equal(t, ctis.DataFlowLocationPropagator, inter.Type)
	assert.Equal(t, 1, inter.Index)
	assert.Equal(t, "important: Tainted data concatenated into SQL query", inter.Notes)

	// Sink
	require.Len(t, df.Sinks, 1)
	sink := df.Sinks[0]
	assert.Equal(t, "src/repositories/user_repo.go", sink.Path)
	assert.Equal(t, 25, sink.Line)
	assert.Equal(t, "repositories.UserRepo.Query", sink.Function) // FQN overrides name
	assert.Equal(t, ctis.DataFlowLocationSink, sink.Type)
	assert.Equal(t, 2, sink.Index)
	assert.Equal(t, "essential: SQL query executed with tainted data", sink.Notes)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_ThreadFlowsNotSlice(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			"threadFlows": "not a slice",
		},
	}
	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	assert.Empty(t, result)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_LocationsNotSlice(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": "not a slice",
				},
			},
		},
	}
	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	assert.Empty(t, result)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_MessageNotMap(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{
								"message": "not a map", // should be map[string]any
							},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)
	require.Len(t, result[0].Sources, 1)
	assert.Equal(t, "", result[0].Sources[0].Notes)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_NoPhysicalLocation(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{
								// no physicalLocation, only logicalLocations
								"logicalLocations": []any{
									map[string]any{
										"name": "someFunction",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)
	require.Len(t, result[0].Sources, 1)

	src := result[0].Sources[0]
	assert.Equal(t, "", src.Path)
	assert.Equal(t, 0, src.Line)
	assert.Equal(t, "someFunction", src.Function)
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_ArtifactLocationNotMap(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"artifactLocation": "not a map",
									"region": map[string]any{
										"startLine": float64(5),
									},
								},
							},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)
	require.Len(t, result[0].Sources, 1)

	src := result[0].Sources[0]
	assert.Equal(t, "", src.Path) // no path because artifactLocation not a map
	assert.Equal(t, 5, src.Line)  // region still parsed
}

func TestConvertSARIFCodeFlowsToCTISDataFlows_SnippetNotMap(t *testing.T) {
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"region": map[string]any{
										"startLine": float64(1),
										"snippet":   "not a map",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	result := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, result, 1)
	require.Len(t, result[0].Sources, 1)
	assert.Equal(t, "", result[0].Sources[0].Content)
}

// =============================================================================
// Integration: SARIF -> CTIS -> Domain round-trip
// =============================================================================

func TestRoundTrip_SARIFToCTISToDomain(t *testing.T) {
	// Convert SARIF codeFlows to CTIS DataFlows
	codeFlows := []any{
		map[string]any{
			"threadFlows": []any{
				map[string]any{
					"locations": []any{
						map[string]any{
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"artifactLocation": map[string]any{
										"uri": "src/handler.go",
									},
									"region": map[string]any{
										"startLine":   float64(10),
										"endLine":     float64(10),
										"startColumn": float64(5),
										"endColumn":   float64(40),
										"snippet": map[string]any{
											"text": "input := r.FormValue(\"q\")",
										},
									},
								},
								"logicalLocations": []any{
									map[string]any{
										"name": "HandleSearch",
									},
								},
								"message": map[string]any{
									"text": "Source of user input",
								},
							},
						},
						map[string]any{
							"location": map[string]any{
								"physicalLocation": map[string]any{
									"artifactLocation": map[string]any{
										"uri": "src/db.go",
									},
									"region": map[string]any{
										"startLine": float64(50),
									},
								},
								"message": map[string]any{
									"text": "SQL query executed",
								},
							},
						},
					},
				},
			},
		},
	}

	ctisDataFlows := ConvertSARIFCodeFlowsToCTISDataFlows(codeFlows)
	require.Len(t, ctisDataFlows, 1)

	// Now convert CTIS DataFlow to domain entities
	findingID := shared.NewID()
	flows, locations, err := ConvertCTISDataFlowToFindingDataFlows(findingID, ctisDataFlows[0])
	require.NoError(t, err)
	require.Len(t, flows, 1)
	require.Len(t, locations, 2) // source + sink

	// Verify the domain entities have correct data
	flow := flows[0]
	assert.Equal(t, findingID, flow.FindingID())
	assert.Equal(t, 0, flow.FlowIndex())
	assert.False(t, flow.ID().IsZero())

	// Source location
	srcLoc := locations[0]
	assert.Equal(t, vulnerability.LocationTypeSource, srcLoc.LocationType())
	assert.Equal(t, "src/handler.go", srcLoc.FilePath())
	assert.Equal(t, 10, srcLoc.StartLine())
	assert.Equal(t, 10, srcLoc.EndLine())
	assert.Equal(t, 5, srcLoc.StartColumn())
	assert.Equal(t, 40, srcLoc.EndColumn())
	assert.Equal(t, "input := r.FormValue(\"q\")", srcLoc.Snippet())
	assert.Equal(t, "HandleSearch", srcLoc.FunctionName())
	assert.Equal(t, 0, srcLoc.StepIndex())

	// Sink location
	sinkLoc := locations[1]
	assert.Equal(t, vulnerability.LocationTypeSink, sinkLoc.LocationType())
	assert.Equal(t, "src/db.go", sinkLoc.FilePath())
	assert.Equal(t, 50, sinkLoc.StartLine())
	assert.Equal(t, 1, sinkLoc.StepIndex())
}
