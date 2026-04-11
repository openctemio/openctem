package app

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// FindingImportService handles importing findings from external scanner formats.
type FindingImportService struct {
	findingRepo vulnerability.FindingRepository
	logger      *logger.Logger
}

// NewFindingImportService creates a new import service.
func NewFindingImportService(repo vulnerability.FindingRepository, log *logger.Logger) *FindingImportService {
	return &FindingImportService{findingRepo: repo, logger: log}
}

// ImportResult contains the result of an import operation.
type ImportResult struct {
	Total    int      `json:"total"`
	Created  int      `json:"created"`
	Skipped  int      `json:"skipped"`
	Errors   int      `json:"errors"`
	Messages []string `json:"messages,omitempty"`
}

// ============================================
// Burp Suite XML Import
// ============================================

// BurpIssue represents a single issue in Burp Suite XML export.
type BurpIssue struct {
	XMLName          xml.Name `xml:"issue"`
	SerialNumber     string   `xml:"serialNumber"`
	Type             string   `xml:"type"`
	Name             string   `xml:"name"`
	Host             string   `xml:"host"`
	Path             string   `xml:"path"`
	Location         string   `xml:"location"`
	Severity         string   `xml:"severity"`
	Confidence       string   `xml:"confidence"`
	IssueBackground  string   `xml:"issueBackground"`
	RemediationBG    string   `xml:"remediationBackground"`
	IssueDetail      string   `xml:"issueDetail"`
	RemediationDetail string  `xml:"remediationDetail"`
	RequestResponse  []struct {
		Request  string `xml:"request"`
		Response string `xml:"response"`
	} `xml:"requestresponse"`
}

// BurpIssues is the root XML element.
type BurpIssues struct {
	XMLName xml.Name    `xml:"issues"`
	Issues  []BurpIssue `xml:"issue"`
}

func burpSeverityToInternal(s string) vulnerability.Severity {
	switch strings.ToLower(s) {
	case "high":
		return vulnerability.SeverityHigh
	case "medium":
		return vulnerability.SeverityMedium
	case "low":
		return vulnerability.SeverityLow
	case "information", "info":
		return vulnerability.SeverityInfo
	default:
		return vulnerability.SeverityMedium
	}
}

// stripHTML removes basic HTML tags from Burp description fields.
func stripHTML(s string) string {
	s = strings.ReplaceAll(s, "<br>", "\n")
	s = strings.ReplaceAll(s, "<br/>", "\n")
	s = strings.ReplaceAll(s, "<br />", "\n")
	s = strings.ReplaceAll(s, "<p>", "\n")
	s = strings.ReplaceAll(s, "</p>", "")
	s = strings.ReplaceAll(s, "<li>", "- ")
	s = strings.ReplaceAll(s, "</li>", "\n")
	s = strings.ReplaceAll(s, "<ul>", "")
	s = strings.ReplaceAll(s, "</ul>", "")
	s = strings.ReplaceAll(s, "<b>", "**")
	s = strings.ReplaceAll(s, "</b>", "**")
	s = strings.ReplaceAll(s, "<i>", "_")
	s = strings.ReplaceAll(s, "</i>", "_")
	// Strip remaining tags
	var result strings.Builder
	inTag := false
	for _, r := range s {
		if r == '<' {
			inTag = true
			continue
		}
		if r == '>' {
			inTag = false
			continue
		}
		if !inTag {
			result.WriteRune(r)
		}
	}
	return strings.TrimSpace(result.String())
}

// ImportBurpXML parses Burp Suite XML and creates findings.
func (s *FindingImportService) ImportBurpXML(ctx context.Context, tenantID, campaignID string, reader io.Reader) (*ImportResult, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant_id", shared.ErrValidation)
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read XML: %w", err)
	}

	var burp BurpIssues
	if err := xml.Unmarshal(data, &burp); err != nil {
		return nil, fmt.Errorf("invalid Burp XML format: %w", err)
	}

	result := &ImportResult{Total: len(burp.Issues)}

	for _, issue := range burp.Issues {
		description := stripHTML(issue.IssueBackground)
		if issue.IssueDetail != "" {
			description += "\n\n" + stripHTML(issue.IssueDetail)
		}

		target := issue.Host
		if issue.Path != "" {
			target += issue.Path
		}

		// Build source metadata for pentest fields
		meta := map[string]any{
			"affected_assets":      []string{target},
			"remediation_guidance": stripHTML(issue.RemediationBG + "\n" + issue.RemediationDetail),
			"burp_type":            issue.Type,
			"burp_confidence":      issue.Confidence,
		}

		if len(issue.RequestResponse) > 0 {
			rrs := make([]map[string]any, 0, len(issue.RequestResponse))
			for _, rr := range issue.RequestResponse {
				rrs = append(rrs, map[string]any{
					"request":  rr.Request,
					"response": rr.Response,
				})
			}
			meta["request_responses"] = rrs
		}

		metaBytes, _ := json.Marshal(meta)
		var metaMap map[string]any
		_ = json.Unmarshal(metaBytes, &metaMap)

		severity := burpSeverityToInternal(issue.Severity)

		finding, fErr := vulnerability.NewFinding(
			tid, shared.ID{},
			vulnerability.FindingSourcePentest, "burp_suite",
			severity, issue.Name,
		)
		if fErr != nil {
			result.Errors++
			result.Messages = append(result.Messages, fmt.Sprintf("Failed to create finding '%s': %v", issue.Name, fErr))
			continue
		}

		finding.SetDescription(description)
		finding.SetSourceMetadata(metaMap)
		if campaignID != "" {
			cid, _ := shared.IDFromString(campaignID)
			finding.SetPentestCampaignID(&cid)
		}

		if err := s.findingRepo.Create(ctx, finding); err != nil {
			result.Errors++
			result.Messages = append(result.Messages, fmt.Sprintf("Failed to save '%s': %v", issue.Name, err))
			continue
		}
		result.Created++
	}

	result.Skipped = result.Total - result.Created - result.Errors
	s.logger.Info("Burp XML import completed", "total", result.Total, "created", result.Created, "errors", result.Errors)
	return result, nil
}

// ============================================
// Generic CSV Import
// ============================================

// ImportCSV parses CSV with headers and creates findings.
// Expected headers: title, severity, description, affected_assets, steps_to_reproduce, poc_code, business_impact, remediation
func (s *FindingImportService) ImportCSV(ctx context.Context, tenantID, campaignID string, reader io.Reader) (*ImportResult, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant_id", shared.ErrValidation)
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("%w: CSV must have header + at least 1 row", shared.ErrValidation)
	}

	// Parse headers
	headers := parseCSVLine(lines[0])
	headerMap := make(map[string]int)
	for i, h := range headers {
		headerMap[strings.TrimSpace(strings.ToLower(h))] = i
	}

	// Required: title
	titleIdx, ok := headerMap["title"]
	if !ok {
		return nil, fmt.Errorf("%w: CSV must have 'title' column", shared.ErrValidation)
	}

	result := &ImportResult{Total: len(lines) - 1}

	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			result.Total--
			continue
		}

		cols := parseCSVLine(line)
		getCol := func(name string) string {
			if idx, ok := headerMap[name]; ok && idx < len(cols) {
				return strings.TrimSpace(cols[idx])
			}
			return ""
		}

		title := ""
		if titleIdx < len(cols) {
			title = strings.TrimSpace(cols[titleIdx])
		}
		if title == "" {
			result.Skipped++
			continue
		}

		severity, _ := vulnerability.ParseSeverity(getCol("severity"))
		if severity == "" {
			severity = vulnerability.SeverityMedium
		}

		meta := map[string]any{}
		if v := getCol("affected_assets"); v != "" {
			meta["affected_assets"] = strings.Split(v, ";")
		}
		if v := getCol("steps_to_reproduce"); v != "" {
			meta["steps_to_reproduce"] = strings.Split(v, ";")
		}
		if v := getCol("poc_code"); v != "" {
			meta["poc_code"] = v
		}
		if v := getCol("business_impact"); v != "" {
			meta["business_impact"] = v
		}
		if v := getCol("remediation"); v != "" {
			meta["remediation_guidance"] = v
		}

		finding, fErr := vulnerability.NewFinding(
			tid, shared.ID{},
			vulnerability.FindingSourcePentest, "csv_import",
			severity, title,
		)
		if fErr != nil {
			result.Errors++
			continue
		}

		if desc := getCol("description"); desc != "" {
			finding.SetDescription(desc)
		}
		finding.SetSourceMetadata(meta)
		if campaignID != "" {
			cid, _ := shared.IDFromString(campaignID)
			finding.SetPentestCampaignID(&cid)
		}

		if err := s.findingRepo.Create(ctx, finding); err != nil {
			result.Errors++
			continue
		}
		result.Created++
	}

	result.Skipped = result.Total - result.Created - result.Errors
	s.logger.Info("CSV import completed", "total", result.Total, "created", result.Created)
	return result, nil
}

// parseCSVLine splits a CSV line respecting quoted fields.
func parseCSVLine(line string) []string {
	var fields []string
	var field strings.Builder
	inQuotes := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '"' {
			if inQuotes && i+1 < len(line) && line[i+1] == '"' {
				field.WriteByte('"')
				i++
			} else {
				inQuotes = !inQuotes
			}
		} else if c == ',' && !inQuotes {
			fields = append(fields, field.String())
			field.Reset()
		} else {
			field.WriteByte(c)
		}
	}
	fields = append(fields, field.String())
	return fields
}
