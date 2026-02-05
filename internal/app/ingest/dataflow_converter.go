package ingest

import (
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/sdk/pkg/eis"
)

// ConvertRISDataFlowToFindingDataFlows converts a EIS DataFlow to domain FindingDataFlow and FindingFlowLocations.
// This function bridges the gap between the EIS input schema and the domain entities.
//
// Returns:
// - flows: slice of FindingDataFlow (usually 1, but could be more for complex flows)
// - locations: slice of FindingFlowLocation for all flows
// - error: if validation fails
func ConvertRISDataFlowToFindingDataFlows(
	findingID shared.ID,
	eisDataFlow *eis.DataFlow,
) ([]*vulnerability.FindingDataFlow, []*vulnerability.FindingFlowLocation, error) {
	if eisDataFlow == nil {
		return nil, nil, nil
	}

	// Create the main FindingDataFlow from EIS DataFlow
	flow, err := vulnerability.NewFindingDataFlow(
		findingID,
		0, // flowIndex (first flow)
		eisDataFlow.Summary,
		"essential",
	)
	if err != nil {
		return nil, nil, err
	}

	// Pre-allocate locations slice
	totalLocations := len(eisDataFlow.Sources) + len(eisDataFlow.Intermediates) +
		len(eisDataFlow.Sanitizers) + len(eisDataFlow.Sinks)
	locations := make([]*vulnerability.FindingFlowLocation, 0, totalLocations)
	stepIndex := 0

	// Convert sources
	for _, src := range eisDataFlow.Sources {
		loc, err := convertRISLocationToDomain(flow.ID(), stepIndex, vulnerability.LocationTypeSource, src)
		if err != nil {
			return nil, nil, err
		}
		locations = append(locations, loc)
		stepIndex++
	}

	// Convert intermediates
	for _, inter := range eisDataFlow.Intermediates {
		loc, err := convertRISLocationToDomain(flow.ID(), stepIndex, vulnerability.LocationTypeIntermediate, inter)
		if err != nil {
			return nil, nil, err
		}
		locations = append(locations, loc)
		stepIndex++
	}

	// Convert sanitizers
	for _, san := range eisDataFlow.Sanitizers {
		loc, err := convertRISLocationToDomain(flow.ID(), stepIndex, vulnerability.LocationTypeSanitizer, san)
		if err != nil {
			return nil, nil, err
		}
		locations = append(locations, loc)
		stepIndex++
	}

	// Convert sinks
	for _, sink := range eisDataFlow.Sinks {
		loc, err := convertRISLocationToDomain(flow.ID(), stepIndex, vulnerability.LocationTypeSink, sink)
		if err != nil {
			return nil, nil, err
		}
		locations = append(locations, loc)
		stepIndex++
	}

	return []*vulnerability.FindingDataFlow{flow}, locations, nil
}

// convertRISLocationToDomain converts a EIS DataFlowLocation to a domain FindingFlowLocation.
func convertRISLocationToDomain(
	dataFlowID shared.ID,
	stepIndex int,
	locType string,
	eisLoc eis.DataFlowLocation,
) (*vulnerability.FindingFlowLocation, error) {
	loc, err := vulnerability.NewFindingFlowLocation(dataFlowID, stepIndex, locType)
	if err != nil {
		return nil, err
	}

	// Set physical location
	loc.SetPhysicalLocation(
		eisLoc.Path,
		eisLoc.Line,
		eisLoc.EndLine,
		eisLoc.Column,
		eisLoc.EndColumn,
		eisLoc.Content,
	)

	// Set logical location
	loc.SetLogicalLocation(
		eisLoc.Function,
		eisLoc.Class,
		"", // FQN will be computed if needed
		eisLoc.Module,
	)

	// Set context
	loc.SetContext(eisLoc.Label, eisLoc.Notes, 0, "essential")

	return loc, nil
}

// ConvertSARIFCodeFlowsToEISDataFlows converts SARIF codeFlows to EIS DataFlow structures.
// This is useful when ingesting SARIF reports that contain dataflow information.
//
// SARIF codeFlow structure:
// - codeFlows[].threadFlows[].locations[].location
//
// This function flattens SARIF's nested structure into the simpler EIS DataFlow format.
func ConvertSARIFCodeFlowsToEISDataFlows(codeFlows any) []*eis.DataFlow {
	if codeFlows == nil {
		return nil
	}

	// Type assert to expected SARIF structure
	// codeFlows is typically []map[string]any from JSON unmarshaling
	flows, ok := codeFlows.([]any)
	if !ok {
		return nil
	}

	result := make([]*eis.DataFlow, 0, len(flows))

	for _, cf := range flows {
		codeFlow, ok := cf.(map[string]any)
		if !ok {
			continue
		}

		df := convertCodeFlowToDataFlow(codeFlow)
		if df != nil {
			result = append(result, df)
		}
	}

	return result
}

// convertCodeFlowToDataFlow converts a single SARIF codeFlow to a EIS DataFlow.
func convertCodeFlowToDataFlow(codeFlow map[string]any) *eis.DataFlow {
	// Get threadFlows
	threadFlows, ok := codeFlow["threadFlows"].([]any)
	if !ok || len(threadFlows) == 0 {
		return nil
	}

	// Process first threadFlow (most common case)
	threadFlow, ok := threadFlows[0].(map[string]any)
	if !ok {
		return nil
	}

	locations, ok := threadFlow["locations"].([]any)
	if !ok || len(locations) == 0 {
		return nil
	}

	df := &eis.DataFlow{
		Tainted: true, // Default tainted unless marked otherwise
	}

	for i, loc := range locations {
		tfl, ok := loc.(map[string]any)
		if !ok {
			continue
		}

		eisLoc := extractSARIFLocation(tfl)
		eisLoc.Index = i

		// Determine location type based on position
		switch {
		case i == 0:
			eisLoc.Type = eis.DataFlowLocationSource
			eisLoc.TaintState = "tainted"
			df.Sources = append(df.Sources, eisLoc)
		case i == len(locations)-1:
			eisLoc.Type = eis.DataFlowLocationSink
			df.Sinks = append(df.Sinks, eisLoc)
		default:
			eisLoc.Type = eis.DataFlowLocationPropagator
			df.Intermediates = append(df.Intermediates, eisLoc)
		}
	}

	// Build summary
	df.BuildSummary()

	return df
}

// extractSARIFLocation extracts location information from a SARIF threadFlowLocation.
func extractSARIFLocation(tfl map[string]any) eis.DataFlowLocation {
	loc := eis.DataFlowLocation{}

	// Get nested location object
	location, ok := tfl["location"].(map[string]any)
	if !ok {
		return loc
	}

	// Extract physical location
	extractPhysicalLocation(location, &loc)

	// Extract logical location
	extractLogicalLocation(location, &loc)

	// Extract message
	if message, ok := location["message"].(map[string]any); ok {
		if text, ok := message["text"].(string); ok {
			loc.Notes = text
		}
	}

	// Thread flow location specific properties
	if importance, ok := tfl["importance"].(string); ok {
		loc.Notes = importance + ": " + loc.Notes
	}

	return loc
}

// extractPhysicalLocation extracts physical location from SARIF location object.
func extractPhysicalLocation(location map[string]any, loc *eis.DataFlowLocation) {
	physLoc, ok := location["physicalLocation"].(map[string]any)
	if !ok {
		return
	}

	// Artifact location
	if artifact, ok := physLoc["artifactLocation"].(map[string]any); ok {
		if uri, ok := artifact["uri"].(string); ok {
			loc.Path = uri
		}
	}

	// Region
	extractRegion(physLoc, loc)
}

// extractRegion extracts region information from SARIF physical location.
func extractRegion(physLoc map[string]any, loc *eis.DataFlowLocation) {
	region, ok := physLoc["region"].(map[string]any)
	if !ok {
		return
	}

	if startLine, ok := region["startLine"].(float64); ok {
		loc.Line = int(startLine)
	}
	if endLine, ok := region["endLine"].(float64); ok {
		loc.EndLine = int(endLine)
	}
	if startColumn, ok := region["startColumn"].(float64); ok {
		loc.Column = int(startColumn)
	}
	if endColumn, ok := region["endColumn"].(float64); ok {
		loc.EndColumn = int(endColumn)
	}
	if snippet, ok := region["snippet"].(map[string]any); ok {
		if text, ok := snippet["text"].(string); ok {
			loc.Content = text
		}
	}
}

// extractLogicalLocation extracts logical location from SARIF location object.
func extractLogicalLocation(location map[string]any, loc *eis.DataFlowLocation) {
	logicalLocs, ok := location["logicalLocations"].([]any)
	if !ok || len(logicalLocs) == 0 {
		return
	}

	logLoc, ok := logicalLocs[0].(map[string]any)
	if !ok {
		return
	}

	if name, ok := logLoc["name"].(string); ok {
		loc.Function = name
	}
	if fqn, ok := logLoc["fullyQualifiedName"].(string); ok {
		loc.Function = fqn
	}
}
