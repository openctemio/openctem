/*
Package sarif provides a comprehensive parser and utilities for SARIF
(Static Analysis Results Interchange Format) version 2.1.0.

SARIF is an OASIS standard format for the output of static analysis tools.
This package implements the full SARIF 2.1.0 specification as defined at:
https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

# Basic Usage

Parse a SARIF file:

	parser := sarif.NewParser(nil)
	log, err := parser.ParseFile("results.sarif")
	if err != nil {
		log.Fatal(err)
	}

Parse from bytes or reader:

	log, err := parser.ParseBytes(data)
	log, err := parser.Parse(reader)

# Parser Options

Configure parser behavior with Options:

	opts := &sarif.Options{
		StrictMode:           true,       // Enable strict validation
		IncludePassedResults: false,      // Exclude passing results
		IncludeSuppressed:    false,      // Exclude suppressed results
		MinLevel:             sarif.LevelWarning, // Filter by minimum level
		MaxResults:           100,        // Limit number of results
	}
	parser := sarif.NewParser(opts)

# Working with Results

Get all results:

	results := sarif.GetAllResults(log)

Filter by severity level:

	errors := sarif.GetResultsByLevel(log, sarif.LevelError)
	warnings := sarif.GetResultsByLevel(log, sarif.LevelWarning)

Filter by rule ID:

	results := sarif.GetResultsByRuleID(log, "RULE001")

Count results by level:

	counts := sarif.CountByLevel(log)
	fmt.Printf("Errors: %d, Warnings: %d\n", counts[sarif.LevelError], counts[sarif.LevelWarning])

Get a summary:

	summary := sarif.GetSummary(log)
	fmt.Printf("Total: %d results from %d runs\n", summary.TotalResults, summary.RunCount)

# Converting to Findings

Extract results to a normalized Finding format:

	findings := sarif.ExtractFindings(log)
	for _, f := range findings {
		fmt.Printf("[%s] %s: %s at %s:%d\n",
			f.Level, f.RuleID, f.Message, f.FilePath, f.StartLine)
	}

Group findings:

	byFile := sarif.GroupFindingsByFile(findings)
	byRule := sarif.GroupFindingsByRule(findings)
	byLevel := sarif.GroupFindingsByLevel(findings)

Filter findings:

	goFindings := sarif.FilterFindingsByExtension(findings, ".go")
	srcFindings := sarif.FilterFindingsByPath(findings, "src/")

Deduplicate findings:

	unique := sarif.DeduplicateFindings(findings)

# Merging Multiple SARIF Logs

Combine results from multiple tools:

	merged := sarif.MergeLogs(log1, log2, log3)

# Severity Levels

SARIF defines four severity levels:

	sarif.LevelError   - High severity, should be fixed
	sarif.LevelWarning - Medium severity, should be reviewed
	sarif.LevelNote    - Low severity, informational
	sarif.LevelNone    - No severity specified

Convert between levels and numeric severity:

	severity := sarif.LevelToSeverity(sarif.LevelError) // Returns 8.0
	level := sarif.SeverityToLevel(5.0)                 // Returns LevelWarning

# Result Kinds

SARIF results can have different kinds:

	sarif.KindFail          - A defect was found
	sarif.KindPass          - The check passed
	sarif.KindNotApplicable - The rule was not applicable
	sarif.KindOpen          - Review needed
	sarif.KindReview        - Manual review needed
	sarif.KindInformational - Informational only

# Supported Tools

This parser works with SARIF output from various static analysis tools including:

  - CodeQL (GitHub)
  - Semgrep
  - ESLint (with SARIF reporter)
  - Trivy
  - Bandit
  - Checkov
  - KICS
  - Tfsec
  - And many more tools that support SARIF 2.1.0 output

# Thread Safety

The Parser is safe for concurrent use. Each Parse* method creates independent
result objects. However, the returned Log objects are not thread-safe and
should not be modified concurrently.

# Performance Considerations

For large SARIF files:

  - Use MaxResults option to limit results if you only need a subset
  - Use MinLevel to filter out low-severity results early
  - Consider streaming parsing for very large files (not yet implemented)

# Error Handling

The parser returns specific errors for common issues:

	sarif.ErrInvalidSARIF      - The input is not valid JSON or SARIF
	sarif.ErrUnsupportedVersion - The SARIF version is not supported
	sarif.ErrEmptyRuns         - The SARIF log contains no runs
*/
package sarif
