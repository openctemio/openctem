// Package defectdojo wires the DefectDojo co-existence connector (RFC-013): pull
// findings from a tenant's DefectDojo integration, convert to CTIS, and ingest
// them — with OpenCTEM remaining the system of record. One-way (DD → OpenCTEM).
package defectdojo

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/internal/app/ingest"
	ddimport "github.com/openctemio/api/internal/infra/importer/defectdojo"
	"github.com/openctemio/api/pkg/crypto"
	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// ErrNoDefectDojoIntegration is returned when the tenant has no connected
// DefectDojo integration to sync from.
var ErrNoDefectDojoIntegration = fmt.Errorf("%w: no connected DefectDojo integration", shared.ErrNotFound)

// Ingester is the narrow slice of the ingest service the sync needs.
type Ingester interface {
	Ingest(ctx context.Context, agt *agent.Agent, input ingest.Input) (*ingest.Output, error)
}

// findingsClient is the read-only DefectDojo surface the sync needs (injectable
// for tests). Satisfied by *importer/defectdojo.Client.
type findingsClient interface {
	FetchFindings(ctx context.Context, filter ddimport.FindingFilter) ([]ddimport.Finding, error)
}

// SyncService pulls a tenant's DefectDojo findings and ingests them as CTIS.
type SyncService struct {
	integrations integration.Repository
	ingester     Ingester
	decrypt      func(string) (string, error)
	// newClient builds the DefectDojo client; overridable in tests.
	newClient func(baseURL, token string) findingsClient
	logger    *logger.Logger
}

// NewSyncService wires the sync service. A nil encryptor treats stored
// credentials as plaintext (dev only), matching the other resolvers.
func NewSyncService(repo integration.Repository, ingester Ingester, encryptor crypto.Encryptor, log *logger.Logger) *SyncService {
	decrypt := func(s string) (string, error) { return s, nil }
	if encryptor != nil {
		decrypt = encryptor.DecryptString
	}
	return &SyncService{
		integrations: repo,
		ingester:     ingester,
		decrypt:      decrypt,
		newClient: func(baseURL, token string) findingsClient {
			return ddimport.NewClient(baseURL, token, nil)
		},
		logger: log.With("service", "defectdojo-sync"),
	}
}

// SyncResult summarizes a completed sync.
type SyncResult struct {
	FindingsPulled  int    `json:"findings_pulled"`
	FindingsCreated int    `json:"findings_created"`
	FindingsUpdated int    `json:"findings_updated"`
	ReportID        string `json:"report_id,omitempty"`
}

// SyncTenant pulls the given tenant's DefectDojo findings and ingests them.
//
// Tenant isolation (standing rule): the tenant is the AUTHENTICATED tenantID —
// credentials are loaded via ListByProvider(tenantID) and the ingest runs under
// a synthetic agent scoped to that same tenant. Nothing in the DefectDojo
// payload can redirect the tenant.
func (s *SyncService) SyncTenant(ctx context.Context, tenantID shared.ID) (*SyncResult, error) {
	if tenantID.IsZero() {
		return nil, fmt.Errorf("%w: tenant id is required", shared.ErrValidation)
	}

	intg, err := s.resolveConnected(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	token, err := s.credsToken(intg)
	if err != nil {
		return nil, err
	}

	client := s.newClient(intg.BaseURL(), token)

	filter := ddimport.FindingFilter{ActiveOnly: true}
	if p := configString(intg, "product"); p != "" {
		filter.Product = p
	}

	findings, err := client.FetchFindings(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("defectdojo fetch: %w", err)
	}

	report := ddimport.Convert(findings, ddimport.ConvertOptions{
		SourceRef:   "defectdojo:" + intg.ID().String(),
		ProductName: configString(intg, "product_name"),
		Now:         time.Now().UTC(),
	})

	// Ingest under a synthetic agent bound to the authenticated tenant. Coverage
	// is partial (report already marks it) so the import never auto-resolves
	// native findings.
	agt := &agent.Agent{TenantID: &tenantID, Status: agent.AgentStatusActive}
	out, err := s.ingester.Ingest(ctx, agt, ingest.Input{
		Report:       report,
		CoverageType: ingest.CoverageTypePartial,
	})
	if err != nil {
		return nil, fmt.Errorf("defectdojo ingest: %w", err)
	}

	s.logger.Info("defectdojo sync complete",
		"tenant_id", tenantID.String(),
		"integration_id", intg.ID().String(),
		"pulled", len(findings),
		"created", out.FindingsCreated,
		"updated", out.FindingsUpdated,
	)
	return &SyncResult{
		FindingsPulled:  len(findings),
		FindingsCreated: out.FindingsCreated,
		FindingsUpdated: out.FindingsUpdated,
		ReportID:        out.ReportID,
	}, nil
}

// resolveConnected returns the tenant's first connected DefectDojo integration.
func (s *SyncService) resolveConnected(ctx context.Context, tenantID shared.ID) (*integration.Integration, error) {
	integrations, err := s.integrations.ListByProvider(ctx, tenantID, integration.ProviderDefectDojo)
	if err != nil {
		return nil, fmt.Errorf("list defectdojo integrations: %w", err)
	}
	for _, intg := range integrations {
		if intg.Status() == integration.StatusConnected {
			return intg, nil
		}
	}
	return nil, ErrNoDefectDojoIntegration
}

// credsToken decrypts and extracts the DefectDojo API token. Stored credentials
// may be a JSON object {"api_token": "..."} or a bare token string.
func (s *SyncService) credsToken(intg *integration.Integration) (string, error) {
	enc := intg.CredentialsEncrypted()
	if strings.TrimSpace(enc) == "" {
		return "", fmt.Errorf("%w: defectdojo integration has no credentials", shared.ErrValidation)
	}
	plain, err := s.decrypt(enc)
	if err != nil {
		return "", fmt.Errorf("decrypt defectdojo credentials: %w", err)
	}
	plain = strings.TrimSpace(plain)

	var creds struct {
		APIToken string `json:"api_token"`
		Token    string `json:"token"`
	}
	if strings.HasPrefix(plain, "{") {
		if err := json.Unmarshal([]byte(plain), &creds); err == nil {
			if t := firstNonEmpty(creds.APIToken, creds.Token); t != "" {
				return t, nil
			}
		}
	}
	return plain, nil // bare token
}

func configString(intg *integration.Integration, key string) string {
	if v, ok := intg.Config()[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
