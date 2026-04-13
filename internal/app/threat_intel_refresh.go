package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/logger"
)

// ThreatIntelRefresher handles automated EPSS and KEV data refresh.
type ThreatIntelRefresher struct {
	logger *logger.Logger
	client *http.Client
}

// NewThreatIntelRefresher creates a new refresher.
func NewThreatIntelRefresher(log *logger.Logger) *ThreatIntelRefresher {
	return &ThreatIntelRefresher{
		logger: log,
		client: &http.Client{Timeout: 60 * time.Second},
	}
}

// EPSSScore represents an EPSS score entry.
type EPSSScore struct {
	CVE   string  `json:"cve"`
	EPSS  float64 `json:"epss"`
	Model string  `json:"model"`
	Date  string  `json:"date"`
}

// KEVEntry represents a CISA KEV catalog entry.
type KEVEntry struct {
	CVEID                 string `json:"cveID"`
	VendorProject         string `json:"vendorProject"`
	Product               string `json:"product"`
	VulnerabilityName     string `json:"vulnerabilityName"`
	DateAdded             string `json:"dateAdded"`
	ShortDescription      string `json:"shortDescription"`
	RequiredAction        string `json:"requiredAction"`
	DueDate               string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}

// FetchEPSSScores fetches EPSS scores from FIRST.org API.
// Returns top 1000 CVEs by EPSS score.
func (r *ThreatIntelRefresher) FetchEPSSScores(ctx context.Context) ([]EPSSScore, error) {
	url := "https://api.first.org/data/v1/epss?order=!epss&limit=1000"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create EPSS request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch EPSS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EPSS API returned %d", resp.StatusCode)
	}

	var result struct {
		Data []struct {
			CVE        string `json:"cve"`
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
			Date       string `json:"date"`
			Model      string `json:"model_version"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode EPSS response: %w", err)
	}

	scores := make([]EPSSScore, 0, len(result.Data))
	for _, d := range result.Data {
		epss, _ := strconv.ParseFloat(d.EPSS, 64)
		scores = append(scores, EPSSScore{
			CVE:   d.CVE,
			EPSS:  epss,
			Model: d.Model,
			Date:  d.Date,
		})
	}

	r.logger.Info("fetched EPSS scores", "count", len(scores))
	return scores, nil
}

// FetchKEVCatalog fetches CISA Known Exploited Vulnerabilities catalog.
func (r *ThreatIntelRefresher) FetchKEVCatalog(ctx context.Context) ([]KEVEntry, error) {
	url := "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create KEV request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch KEV: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("KEV API returned %d", resp.StatusCode)
	}

	var catalog struct {
		Vulnerabilities []KEVEntry `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("failed to decode KEV response: %w", err)
	}

	r.logger.Info("fetched KEV catalog", "count", len(catalog.Vulnerabilities))
	return catalog.Vulnerabilities, nil
}

// FetchEPSSForCVEs fetches EPSS scores for specific CVE IDs.
func (r *ThreatIntelRefresher) FetchEPSSForCVEs(ctx context.Context, cveIDs []string) ([]EPSSScore, error) {
	if len(cveIDs) == 0 {
		return nil, nil
	}

	// FIRST.org API accepts comma-separated CVE list
	url := fmt.Sprintf("https://api.first.org/data/v1/epss?cve=%s", strings.Join(cveIDs, ","))

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create EPSS request: %w", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch EPSS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EPSS API returned %d", resp.StatusCode)
	}

	var result struct {
		Data []struct {
			CVE  string `json:"cve"`
			EPSS string `json:"epss"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode EPSS response: %w", err)
	}

	scores := make([]EPSSScore, 0, len(result.Data))
	for _, d := range result.Data {
		epss, _ := strconv.ParseFloat(d.EPSS, 64)
		scores = append(scores, EPSSScore{CVE: d.CVE, EPSS: epss})
	}

	return scores, nil
}

