package unit

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/crypto"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/webhook"
	"github.com/openctemio/api/pkg/logger"
)

// =============================================================================
// Mock Webhook Repository
// =============================================================================

type mockWebhookRepo struct {
	webhooks map[shared.ID]*webhook.Webhook

	// Error overrides
	createErr         error
	getByIDErr        error
	updateErr         error
	deleteErr         error
	listErr           error
	listDeliveriesErr error

	// Call tracking
	createCalls         int
	getByIDCalls        int
	updateCalls         int
	deleteCalls         int
	listCalls           int
	listDeliveriesCalls int

	// Capture last filter
	lastFilter         webhook.Filter
	lastDeliveryFilter webhook.DeliveryFilter
	lastDeleteID       shared.ID
	lastDeleteTenantID shared.ID
}

func newMockWebhookRepo() *mockWebhookRepo {
	return &mockWebhookRepo{
		webhooks: make(map[shared.ID]*webhook.Webhook),
	}
}

func (m *mockWebhookRepo) Create(_ context.Context, w *webhook.Webhook) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	m.webhooks[w.ID()] = w
	return nil
}

func (m *mockWebhookRepo) GetByID(_ context.Context, id, tenantID shared.ID) (*webhook.Webhook, error) {
	m.getByIDCalls++
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	w, ok := m.webhooks[id]
	if !ok {
		return nil, webhook.ErrWebhookNotFound
	}
	// Enforce tenant isolation
	if w.TenantID() != tenantID {
		return nil, webhook.ErrWebhookNotFound
	}
	return w, nil
}

func (m *mockWebhookRepo) List(_ context.Context, filter webhook.Filter) (webhook.ListResult, error) {
	m.listCalls++
	m.lastFilter = filter
	if m.listErr != nil {
		return webhook.ListResult{}, m.listErr
	}

	var results []*webhook.Webhook
	for _, w := range m.webhooks {
		if filter.TenantID != nil && w.TenantID() != *filter.TenantID {
			continue
		}
		if filter.Status != nil && w.Status() != *filter.Status {
			continue
		}
		results = append(results, w)
	}

	return webhook.ListResult{
		Data:       results,
		Total:      int64(len(results)),
		Page:       filter.Page,
		PerPage:    filter.PerPage,
		TotalPages: 1,
	}, nil
}

func (m *mockWebhookRepo) Update(_ context.Context, w *webhook.Webhook) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	m.webhooks[w.ID()] = w
	return nil
}

func (m *mockWebhookRepo) Delete(_ context.Context, id, tenantID shared.ID) error {
	m.deleteCalls++
	m.lastDeleteID = id
	m.lastDeleteTenantID = tenantID
	if m.deleteErr != nil {
		return m.deleteErr
	}
	for wID, w := range m.webhooks {
		if wID == id && w.TenantID() == tenantID {
			delete(m.webhooks, wID)
			return nil
		}
	}
	return webhook.ErrWebhookNotFound
}

func (m *mockWebhookRepo) ListDeliveries(_ context.Context, filter webhook.DeliveryFilter) (webhook.DeliveryListResult, error) {
	m.listDeliveriesCalls++
	m.lastDeliveryFilter = filter
	if m.listDeliveriesErr != nil {
		return webhook.DeliveryListResult{}, m.listDeliveriesErr
	}
	return webhook.DeliveryListResult{
		Data:       []*webhook.Delivery{},
		Total:      0,
		Page:       filter.Page,
		PerPage:    filter.PerPage,
		TotalPages: 0,
	}, nil
}

// =============================================================================
// Mock Encryptor for Webhook Tests
// =============================================================================

type mockWebhookEncryptor struct {
	encryptErr   error
	decryptErr   error
	encryptCalls int
	decryptCalls int
	prefix       string
}

func newMockWebhookEncryptor() *mockWebhookEncryptor {
	return &mockWebhookEncryptor{
		prefix: "encrypted:",
	}
}

func (m *mockWebhookEncryptor) EncryptString(plaintext string) (string, error) {
	m.encryptCalls++
	if m.encryptErr != nil {
		return "", m.encryptErr
	}
	return m.prefix + plaintext, nil
}

func (m *mockWebhookEncryptor) DecryptString(encoded string) (string, error) {
	m.decryptCalls++
	if m.decryptErr != nil {
		return "", m.decryptErr
	}
	return encoded, nil
}

// =============================================================================
// Helper: create WebhookService for tests
// =============================================================================

func newTestWebhookService(repo *mockWebhookRepo, enc crypto.Encryptor) *app.WebhookService {
	log := logger.NewNop()
	return app.NewWebhookService(repo, enc, log)
}

// =============================================================================
// Test: CreateWebhook
// =============================================================================

func TestWebhookService_CreateWebhook(t *testing.T) {
	tenantID := shared.NewID()

	tests := []struct {
		name      string
		input     app.CreateWebhookInput
		setupRepo func(*mockWebhookRepo)
		setupEnc  func(*mockWebhookEncryptor)
		wantErr   bool
		errIs     error
		validate  func(t *testing.T, w *webhook.Webhook, enc *mockWebhookEncryptor, repo *mockWebhookRepo)
	}{
		{
			name: "success - minimal fields",
			input: app.CreateWebhookInput{
				TenantID:   tenantID.String(),
				Name:       "My Webhook",
				URL:        "https://example.com/hook",
				EventTypes: []string{"finding.created"},
			},
			wantErr: false,
			validate: func(t *testing.T, w *webhook.Webhook, enc *mockWebhookEncryptor, repo *mockWebhookRepo) {
				if w.Name() != "My Webhook" {
					t.Errorf("expected name 'My Webhook', got %q", w.Name())
				}
				if w.URL() != "https://example.com/hook" {
					t.Errorf("expected URL 'https://example.com/hook', got %q", w.URL())
				}
				if w.TenantID() != tenantID {
					t.Errorf("expected tenant ID %s, got %s", tenantID, w.TenantID())
				}
				if w.Status() != webhook.StatusActive {
					t.Errorf("expected status active, got %s", w.Status())
				}
				if repo.createCalls != 1 {
					t.Errorf("expected 1 create call, got %d", repo.createCalls)
				}
			},
		},
		{
			name: "success - all fields",
			input: app.CreateWebhookInput{
				TenantID:          tenantID.String(),
				Name:              "Full Webhook",
				Description:       "A test webhook",
				URL:               "https://hooks.example.com/receive",
				Secret:            "my-secret-123",
				EventTypes:        []string{"finding.created", "finding.updated"},
				SeverityThreshold: "critical",
				MaxRetries:        5,
				RetryInterval:     120,
				CreatedBy:         shared.NewID().String(),
			},
			wantErr: false,
			validate: func(t *testing.T, w *webhook.Webhook, enc *mockWebhookEncryptor, repo *mockWebhookRepo) {
				if w.Description() != "A test webhook" {
					t.Errorf("expected description 'A test webhook', got %q", w.Description())
				}
				if w.SeverityThreshold() != "critical" {
					t.Errorf("expected severity threshold 'critical', got %q", w.SeverityThreshold())
				}
				if w.MaxRetries() != 5 {
					t.Errorf("expected max retries 5, got %d", w.MaxRetries())
				}
				if w.RetryIntervalSeconds() != 120 {
					t.Errorf("expected retry interval 120, got %d", w.RetryIntervalSeconds())
				}
				if enc.encryptCalls != 1 {
					t.Errorf("expected 1 encrypt call, got %d", enc.encryptCalls)
				}
				// Secret should have been encrypted
				if len(w.SecretEncrypted()) == 0 {
					t.Error("expected secret to be set")
				}
				if w.CreatedBy() == nil {
					t.Error("expected created_by to be set")
				}
			},
		},
		{
			name: "error - invalid tenant ID",
			input: app.CreateWebhookInput{
				TenantID:   "not-a-uuid",
				Name:       "Test",
				URL:        "https://example.com/hook",
				EventTypes: []string{"finding.created"},
			},
			wantErr: true,
			errIs:   shared.ErrValidation,
		},
		{
			name: "error - empty tenant ID",
			input: app.CreateWebhookInput{
				TenantID:   "",
				Name:       "Test",
				URL:        "https://example.com/hook",
				EventTypes: []string{"finding.created"},
			},
			wantErr: true,
			errIs:   shared.ErrValidation,
		},
		{
			name: "error - localhost URL (SSRF protection)",
			input: app.CreateWebhookInput{
				TenantID:   tenantID.String(),
				Name:       "Localhost Hook",
				URL:        "https://localhost/hook",
				EventTypes: []string{"finding.created"},
			},
			wantErr: true,
			errIs:   shared.ErrValidation,
		},
		{
			name: "error - 127.0.0.1 URL (SSRF protection)",
			input: app.CreateWebhookInput{
				TenantID:   tenantID.String(),
				Name:       "Loopback Hook",
				URL:        "https://127.0.0.1/hook",
				EventTypes: []string{"finding.created"},
			},
			wantErr: true,
			errIs:   shared.ErrValidation,
		},
		{
			name: "error - cloud metadata URL (SSRF protection)",
			input: app.CreateWebhookInput{
				TenantID:   tenantID.String(),
				Name:       "Metadata Hook",
				URL:        "http://169.254.169.254/latest/meta-data/",
				EventTypes: []string{"finding.created"},
			},
			wantErr: true,
			errIs:   shared.ErrValidation,
		},
		{
			name: "error - private IP 10.x (SSRF protection)",
			input: app.CreateWebhookInput{
				TenantID:   tenantID.String(),
				Name:       "Private Hook",
				URL:        "http://10.0.0.1/hook",
				EventTypes: []string{"finding.created"},
			},
			wantErr: true,
			errIs:   shared.ErrValidation,
		},
		{
			name: "error - private IP 192.168.x (SSRF protection)",
			input: app.CreateWebhookInput{
				TenantID:   tenantID.String(),
				Name:       "Private Hook 192",
				URL:        "http://192.168.1.1/hook",
				EventTypes: []string{"finding.created"},
			},
			wantErr: true,
			errIs:   shared.ErrValidation,
		},
		{
			name: "error - ftp scheme rejected",
			input: app.CreateWebhookInput{
				TenantID:   tenantID.String(),
				Name:       "FTP Hook",
				URL:        "ftp://example.com/hook",
				EventTypes: []string{"finding.created"},
			},
			wantErr: true,
			errIs:   shared.ErrValidation,
		},
		{
			name: "error - encryption failure",
			input: app.CreateWebhookInput{
				TenantID:   tenantID.String(),
				Name:       "Secret Hook",
				URL:        "https://example.com/hook",
				Secret:     "my-secret",
				EventTypes: []string{"finding.created"},
			},
			setupEnc: func(enc *mockWebhookEncryptor) {
				enc.encryptErr = fmt.Errorf("encryption failed")
			},
			wantErr: true,
		},
		{
			name: "error - repository create failure",
			input: app.CreateWebhookInput{
				TenantID:   tenantID.String(),
				Name:       "Repo Fail Hook",
				URL:        "https://example.com/hook",
				EventTypes: []string{"finding.created"},
			},
			setupRepo: func(repo *mockWebhookRepo) {
				repo.createErr = fmt.Errorf("db connection lost")
			},
			wantErr: true,
		},
		{
			name: "error - duplicate name from repo",
			input: app.CreateWebhookInput{
				TenantID:   tenantID.String(),
				Name:       "Duplicate",
				URL:        "https://example.com/hook",
				EventTypes: []string{"finding.created"},
			},
			setupRepo: func(repo *mockWebhookRepo) {
				repo.createErr = webhook.ErrWebhookNameExists
			},
			wantErr: true,
			errIs:   shared.ErrAlreadyExists,
		},
		{
			name: "success - no secret means no encryption call",
			input: app.CreateWebhookInput{
				TenantID:   tenantID.String(),
				Name:       "No Secret",
				URL:        "https://example.com/hook",
				EventTypes: []string{"finding.created"},
			},
			wantErr: false,
			validate: func(t *testing.T, w *webhook.Webhook, enc *mockWebhookEncryptor, repo *mockWebhookRepo) {
				if enc.encryptCalls != 0 {
					t.Errorf("expected 0 encrypt calls, got %d", enc.encryptCalls)
				}
				if len(w.SecretEncrypted()) != 0 {
					t.Error("expected no secret")
				}
			},
		},
		{
			name: "success - invalid created_by is silently ignored",
			input: app.CreateWebhookInput{
				TenantID:   tenantID.String(),
				Name:       "Bad CreatedBy",
				URL:        "https://example.com/hook",
				EventTypes: []string{"finding.created"},
				CreatedBy:  "not-a-uuid",
			},
			wantErr: false,
			validate: func(t *testing.T, w *webhook.Webhook, enc *mockWebhookEncryptor, repo *mockWebhookRepo) {
				if w.CreatedBy() != nil {
					t.Error("expected created_by to be nil for invalid UUID")
				}
			},
		},
		{
			name: "success - HTTP URL allowed",
			input: app.CreateWebhookInput{
				TenantID:   tenantID.String(),
				Name:       "HTTP Hook",
				URL:        "http://external.example.com/hook",
				EventTypes: []string{"finding.created"},
			},
			wantErr: false,
		},
		{
			name: "error - 0.0.0.0 URL blocked",
			input: app.CreateWebhookInput{
				TenantID:   tenantID.String(),
				Name:       "Zero IP Hook",
				URL:        "http://0.0.0.0/hook",
				EventTypes: []string{"finding.created"},
			},
			wantErr: true,
			errIs:   shared.ErrValidation,
		},
		{
			name: "error - metadata.google.internal blocked",
			input: app.CreateWebhookInput{
				TenantID:   tenantID.String(),
				Name:       "GCP Metadata Hook",
				URL:        "http://metadata.google.internal/computeMetadata/v1/",
				EventTypes: []string{"finding.created"},
			},
			wantErr: true,
			errIs:   shared.ErrValidation,
		},
		{
			name: "error - IPv6 loopback ::1 blocked",
			input: app.CreateWebhookInput{
				TenantID:   tenantID.String(),
				Name:       "IPv6 Loopback Hook",
				URL:        "http://[::1]/hook",
				EventTypes: []string{"finding.created"},
			},
			wantErr: true,
			errIs:   shared.ErrValidation,
		},
		{
			name: "success - defaults not overridden when zero values",
			input: app.CreateWebhookInput{
				TenantID:   tenantID.String(),
				Name:       "Defaults Hook",
				URL:        "https://example.com/hook",
				EventTypes: []string{"finding.created"},
				MaxRetries: 0,
			},
			wantErr: false,
			validate: func(t *testing.T, w *webhook.Webhook, enc *mockWebhookEncryptor, repo *mockWebhookRepo) {
				// Default max retries is 3 (from NewWebhook)
				if w.MaxRetries() != 3 {
					t.Errorf("expected default max retries 3, got %d", w.MaxRetries())
				}
				// Default severity threshold is "medium"
				if w.SeverityThreshold() != "medium" {
					t.Errorf("expected default severity 'medium', got %q", w.SeverityThreshold())
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := newMockWebhookRepo()
			enc := newMockWebhookEncryptor()

			if tc.setupRepo != nil {
				tc.setupRepo(repo)
			}
			if tc.setupEnc != nil {
				tc.setupEnc(enc)
			}

			svc := newTestWebhookService(repo, enc)
			result, err := svc.CreateWebhook(context.Background(), tc.input)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.errIs != nil && !errors.Is(err, tc.errIs) {
					t.Errorf("expected error wrapping %v, got %v", tc.errIs, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("expected non-nil webhook")
			}

			if tc.validate != nil {
				tc.validate(t, result, enc, repo)
			}
		})
	}
}

// =============================================================================
// Test: ListWebhooks
// =============================================================================

func TestWebhookService_ListWebhooks(t *testing.T) {
	tenantID := shared.NewID()
	otherTenantID := shared.NewID()

	tests := []struct {
		name      string
		input     app.ListWebhooksInput
		setupRepo func(*mockWebhookRepo)
		wantErr   bool
		errIs     error
		validate  func(t *testing.T, result webhook.ListResult, repo *mockWebhookRepo)
	}{
		{
			name: "success - list with valid tenant",
			input: app.ListWebhooksInput{
				TenantID: tenantID.String(),
				Page:     1,
				PerPage:  20,
			},
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(shared.NewID(), tenantID, "Hook 1", "https://example.com/1", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
			},
			wantErr: false,
			validate: func(t *testing.T, result webhook.ListResult, repo *mockWebhookRepo) {
				if result.Total != 1 {
					t.Errorf("expected 1 result, got %d", result.Total)
				}
				if repo.listCalls != 1 {
					t.Errorf("expected 1 list call, got %d", repo.listCalls)
				}
			},
		},
		{
			name: "success - filters by status",
			input: app.ListWebhooksInput{
				TenantID: tenantID.String(),
				Status:   "active",
			},
			setupRepo: func(repo *mockWebhookRepo) {
				w1 := webhook.NewWebhook(shared.NewID(), tenantID, "Active Hook", "https://example.com/1", []string{"finding.created"})
				repo.webhooks[w1.ID()] = w1

				w2 := webhook.NewWebhook(shared.NewID(), tenantID, "Disabled Hook", "https://example.com/2", []string{"finding.created"})
				w2.Disable()
				repo.webhooks[w2.ID()] = w2
			},
			wantErr: false,
			validate: func(t *testing.T, result webhook.ListResult, repo *mockWebhookRepo) {
				if result.Total != 1 {
					t.Errorf("expected 1 active result, got %d", result.Total)
				}
			},
		},
		{
			name: "success - tenant isolation in filter",
			input: app.ListWebhooksInput{
				TenantID: tenantID.String(),
			},
			setupRepo: func(repo *mockWebhookRepo) {
				w1 := webhook.NewWebhook(shared.NewID(), tenantID, "My Hook", "https://example.com/1", []string{"finding.created"})
				repo.webhooks[w1.ID()] = w1
				w2 := webhook.NewWebhook(shared.NewID(), otherTenantID, "Other Hook", "https://example.com/2", []string{"finding.created"})
				repo.webhooks[w2.ID()] = w2
			},
			wantErr: false,
			validate: func(t *testing.T, result webhook.ListResult, repo *mockWebhookRepo) {
				if result.Total != 1 {
					t.Errorf("expected 1 result (tenant-isolated), got %d", result.Total)
				}
			},
		},
		{
			name: "error - invalid tenant ID",
			input: app.ListWebhooksInput{
				TenantID: "bad-uuid",
			},
			wantErr: true,
			errIs:   shared.ErrValidation,
		},
		{
			name: "error - repository failure",
			input: app.ListWebhooksInput{
				TenantID: tenantID.String(),
			},
			setupRepo: func(repo *mockWebhookRepo) {
				repo.listErr = fmt.Errorf("db error")
			},
			wantErr: true,
		},
		{
			name: "success - passes filter fields correctly",
			input: app.ListWebhooksInput{
				TenantID:  tenantID.String(),
				EventType: "finding.created",
				Search:    "my-hook",
				Page:      2,
				PerPage:   10,
				SortBy:    "name",
				SortOrder: "desc",
			},
			wantErr: false,
			validate: func(t *testing.T, result webhook.ListResult, repo *mockWebhookRepo) {
				f := repo.lastFilter
				if f.EventType != "finding.created" {
					t.Errorf("expected event_type 'finding.created', got %q", f.EventType)
				}
				if f.Search != "my-hook" {
					t.Errorf("expected search 'my-hook', got %q", f.Search)
				}
				if f.Page != 2 {
					t.Errorf("expected page 2, got %d", f.Page)
				}
				if f.PerPage != 10 {
					t.Errorf("expected per_page 10, got %d", f.PerPage)
				}
				if f.SortBy != "name" {
					t.Errorf("expected sort_by 'name', got %q", f.SortBy)
				}
				if f.SortOrder != "desc" {
					t.Errorf("expected sort_order 'desc', got %q", f.SortOrder)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := newMockWebhookRepo()
			enc := newMockWebhookEncryptor()
			if tc.setupRepo != nil {
				tc.setupRepo(repo)
			}

			svc := newTestWebhookService(repo, enc)
			result, err := svc.ListWebhooks(context.Background(), tc.input)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.errIs != nil && !errors.Is(err, tc.errIs) {
					t.Errorf("expected error wrapping %v, got %v", tc.errIs, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.validate != nil {
				tc.validate(t, result, repo)
			}
		})
	}
}

// =============================================================================
// Test: GetWebhook
// =============================================================================

func TestWebhookService_GetWebhook(t *testing.T) {
	tenantID := shared.NewID()
	otherTenantID := shared.NewID()
	webhookID := shared.NewID()

	tests := []struct {
		name        string
		id          string
		tenantIDStr string
		setupRepo   func(*mockWebhookRepo)
		wantErr     bool
		errIs       error
		validate    func(t *testing.T, w *webhook.Webhook)
	}{
		{
			name:        "success - get existing webhook",
			id:          webhookID.String(),
			tenantIDStr: tenantID.String(),
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Test Hook", "https://example.com/hook", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
			},
			wantErr: false,
			validate: func(t *testing.T, w *webhook.Webhook) {
				if w.ID() != webhookID {
					t.Errorf("expected webhook ID %s, got %s", webhookID, w.ID())
				}
				if w.Name() != "Test Hook" {
					t.Errorf("expected name 'Test Hook', got %q", w.Name())
				}
			},
		},
		{
			name:        "error - invalid webhook ID",
			id:          "not-a-uuid",
			tenantIDStr: tenantID.String(),
			wantErr:     true,
			errIs:       shared.ErrValidation,
		},
		{
			name:        "error - invalid tenant ID",
			id:          webhookID.String(),
			tenantIDStr: "not-a-uuid",
			wantErr:     true,
			errIs:       shared.ErrValidation,
		},
		{
			name:        "error - webhook not found",
			id:          shared.NewID().String(),
			tenantIDStr: tenantID.String(),
			wantErr:     true,
			errIs:       shared.ErrNotFound,
		},
		{
			name:        "error - cross-tenant isolation",
			id:          webhookID.String(),
			tenantIDStr: otherTenantID.String(),
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Test Hook", "https://example.com/hook", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
			},
			wantErr: true,
			errIs:   shared.ErrNotFound,
		},
		{
			name:        "error - repository error",
			id:          webhookID.String(),
			tenantIDStr: tenantID.String(),
			setupRepo: func(repo *mockWebhookRepo) {
				repo.getByIDErr = fmt.Errorf("db connection error")
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := newMockWebhookRepo()
			enc := newMockWebhookEncryptor()
			if tc.setupRepo != nil {
				tc.setupRepo(repo)
			}

			svc := newTestWebhookService(repo, enc)
			result, err := svc.GetWebhook(context.Background(), tc.id, tc.tenantIDStr)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.errIs != nil && !errors.Is(err, tc.errIs) {
					t.Errorf("expected error wrapping %v, got %v", tc.errIs, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("expected non-nil webhook")
			}

			if tc.validate != nil {
				tc.validate(t, result)
			}
		})
	}
}

// =============================================================================
// Test: UpdateWebhook
// =============================================================================

func TestWebhookService_UpdateWebhook(t *testing.T) {
	tenantID := shared.NewID()
	webhookID := shared.NewID()

	strPtr := func(s string) *string { return &s }
	intPtr := func(i int) *int { return &i }

	tests := []struct {
		name        string
		id          string
		tenantIDStr string
		input       app.UpdateWebhookInput
		setupRepo   func(*mockWebhookRepo)
		setupEnc    func(*mockWebhookEncryptor)
		wantErr     bool
		errIs       error
		validate    func(t *testing.T, w *webhook.Webhook, enc *mockWebhookEncryptor, repo *mockWebhookRepo)
	}{
		{
			name:        "success - update name only",
			id:          webhookID.String(),
			tenantIDStr: tenantID.String(),
			input: app.UpdateWebhookInput{
				Name: strPtr("Updated Name"),
			},
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Original", "https://example.com/hook", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
			},
			wantErr: false,
			validate: func(t *testing.T, w *webhook.Webhook, enc *mockWebhookEncryptor, repo *mockWebhookRepo) {
				if w.Name() != "Updated Name" {
					t.Errorf("expected name 'Updated Name', got %q", w.Name())
				}
				if repo.updateCalls != 1 {
					t.Errorf("expected 1 update call, got %d", repo.updateCalls)
				}
			},
		},
		{
			name:        "success - update all fields",
			id:          webhookID.String(),
			tenantIDStr: tenantID.String(),
			input: app.UpdateWebhookInput{
				Name:              strPtr("New Name"),
				Description:       strPtr("New Description"),
				URL:               strPtr("https://new.example.com/hook"),
				Secret:            strPtr("new-secret"),
				EventTypes:        []string{"finding.deleted", "scan.completed"},
				SeverityThreshold: strPtr("high"),
				MaxRetries:        intPtr(7),
				RetryInterval:     intPtr(300),
			},
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Old Name", "https://example.com/hook", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
			},
			wantErr: false,
			validate: func(t *testing.T, w *webhook.Webhook, enc *mockWebhookEncryptor, repo *mockWebhookRepo) {
				if w.Name() != "New Name" {
					t.Errorf("expected name 'New Name', got %q", w.Name())
				}
				if w.Description() != "New Description" {
					t.Errorf("expected description 'New Description', got %q", w.Description())
				}
				if w.URL() != "https://new.example.com/hook" {
					t.Errorf("expected URL 'https://new.example.com/hook', got %q", w.URL())
				}
				if w.SeverityThreshold() != "high" {
					t.Errorf("expected severity 'high', got %q", w.SeverityThreshold())
				}
				if w.MaxRetries() != 7 {
					t.Errorf("expected max retries 7, got %d", w.MaxRetries())
				}
				if w.RetryIntervalSeconds() != 300 {
					t.Errorf("expected retry interval 300, got %d", w.RetryIntervalSeconds())
				}
				if enc.encryptCalls != 1 {
					t.Errorf("expected 1 encrypt call, got %d", enc.encryptCalls)
				}
				if len(w.EventTypes()) != 2 {
					t.Errorf("expected 2 event types, got %d", len(w.EventTypes()))
				}
			},
		},
		{
			name:        "success - update with no fields (no-op update)",
			id:          webhookID.String(),
			tenantIDStr: tenantID.String(),
			input:       app.UpdateWebhookInput{},
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Original", "https://example.com/hook", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
			},
			wantErr: false,
			validate: func(t *testing.T, w *webhook.Webhook, enc *mockWebhookEncryptor, repo *mockWebhookRepo) {
				if w.Name() != "Original" {
					t.Errorf("expected name 'Original', got %q", w.Name())
				}
				if repo.updateCalls != 1 {
					t.Errorf("expected 1 update call (even no-op), got %d", repo.updateCalls)
				}
			},
		},
		{
			name:        "error - invalid webhook ID",
			id:          "bad-id",
			tenantIDStr: tenantID.String(),
			input:       app.UpdateWebhookInput{Name: strPtr("X")},
			wantErr:     true,
			errIs:       shared.ErrValidation,
		},
		{
			name:        "error - invalid tenant ID",
			id:          webhookID.String(),
			tenantIDStr: "bad-tenant",
			input:       app.UpdateWebhookInput{Name: strPtr("X")},
			wantErr:     true,
			errIs:       shared.ErrValidation,
		},
		{
			name:        "error - webhook not found",
			id:          shared.NewID().String(),
			tenantIDStr: tenantID.String(),
			input:       app.UpdateWebhookInput{Name: strPtr("X")},
			wantErr:     true,
			errIs:       shared.ErrNotFound,
		},
		{
			name:        "error - cross-tenant update rejected",
			id:          webhookID.String(),
			tenantIDStr: shared.NewID().String(),
			input:       app.UpdateWebhookInput{Name: strPtr("Hacked")},
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Original", "https://example.com/hook", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
			},
			wantErr: true,
			errIs:   shared.ErrNotFound,
		},
		{
			name:        "error - URL update to localhost rejected",
			id:          webhookID.String(),
			tenantIDStr: tenantID.String(),
			input: app.UpdateWebhookInput{
				URL: strPtr("https://localhost/evil"),
			},
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Original", "https://example.com/hook", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
			},
			wantErr: true,
			errIs:   shared.ErrValidation,
		},
		{
			name:        "error - URL update to private IP rejected",
			id:          webhookID.String(),
			tenantIDStr: tenantID.String(),
			input: app.UpdateWebhookInput{
				URL: strPtr("http://10.0.0.5/internal"),
			},
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Original", "https://example.com/hook", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
			},
			wantErr: true,
			errIs:   shared.ErrValidation,
		},
		{
			name:        "error - encryption failure on update",
			id:          webhookID.String(),
			tenantIDStr: tenantID.String(),
			input: app.UpdateWebhookInput{
				Secret: strPtr("new-secret"),
			},
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Original", "https://example.com/hook", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
			},
			setupEnc: func(enc *mockWebhookEncryptor) {
				enc.encryptErr = fmt.Errorf("encryption failure")
			},
			wantErr: true,
		},
		{
			name:        "error - repository update failure",
			id:          webhookID.String(),
			tenantIDStr: tenantID.String(),
			input: app.UpdateWebhookInput{
				Name: strPtr("Updated"),
			},
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Original", "https://example.com/hook", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
				repo.updateErr = fmt.Errorf("db write failure")
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := newMockWebhookRepo()
			enc := newMockWebhookEncryptor()
			if tc.setupRepo != nil {
				tc.setupRepo(repo)
			}
			if tc.setupEnc != nil {
				tc.setupEnc(enc)
			}

			svc := newTestWebhookService(repo, enc)
			result, err := svc.UpdateWebhook(context.Background(), tc.id, tc.tenantIDStr, tc.input)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.errIs != nil && !errors.Is(err, tc.errIs) {
					t.Errorf("expected error wrapping %v, got %v", tc.errIs, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("expected non-nil webhook")
			}

			if tc.validate != nil {
				tc.validate(t, result, enc, repo)
			}
		})
	}
}

// =============================================================================
// Test: EnableWebhook
// =============================================================================

func TestWebhookService_EnableWebhook(t *testing.T) {
	tenantID := shared.NewID()
	webhookID := shared.NewID()

	tests := []struct {
		name        string
		id          string
		tenantIDStr string
		setupRepo   func(*mockWebhookRepo)
		wantErr     bool
		errIs       error
		validate    func(t *testing.T, w *webhook.Webhook, repo *mockWebhookRepo)
	}{
		{
			name:        "success - enable disabled webhook",
			id:          webhookID.String(),
			tenantIDStr: tenantID.String(),
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Disabled Hook", "https://example.com/hook", []string{"finding.created"})
				w.Disable()
				repo.webhooks[w.ID()] = w
			},
			wantErr: false,
			validate: func(t *testing.T, w *webhook.Webhook, repo *mockWebhookRepo) {
				if w.Status() != webhook.StatusActive {
					t.Errorf("expected status active, got %s", w.Status())
				}
				if repo.updateCalls != 1 {
					t.Errorf("expected 1 update call, got %d", repo.updateCalls)
				}
			},
		},
		{
			name:        "success - enable already active webhook (idempotent)",
			id:          webhookID.String(),
			tenantIDStr: tenantID.String(),
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Active Hook", "https://example.com/hook", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
			},
			wantErr: false,
			validate: func(t *testing.T, w *webhook.Webhook, repo *mockWebhookRepo) {
				if w.Status() != webhook.StatusActive {
					t.Errorf("expected status active, got %s", w.Status())
				}
			},
		},
		{
			name:        "error - invalid webhook ID",
			id:          "bad",
			tenantIDStr: tenantID.String(),
			wantErr:     true,
			errIs:       shared.ErrValidation,
		},
		{
			name:        "error - invalid tenant ID",
			id:          webhookID.String(),
			tenantIDStr: "bad",
			wantErr:     true,
			errIs:       shared.ErrValidation,
		},
		{
			name:        "error - webhook not found",
			id:          shared.NewID().String(),
			tenantIDStr: tenantID.String(),
			wantErr:     true,
			errIs:       shared.ErrNotFound,
		},
		{
			name:        "error - cross-tenant enable rejected",
			id:          webhookID.String(),
			tenantIDStr: shared.NewID().String(),
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Hook", "https://example.com/hook", []string{"finding.created"})
				w.Disable()
				repo.webhooks[w.ID()] = w
			},
			wantErr: true,
			errIs:   shared.ErrNotFound,
		},
		{
			name:        "error - repository update failure",
			id:          webhookID.String(),
			tenantIDStr: tenantID.String(),
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Hook", "https://example.com/hook", []string{"finding.created"})
				w.Disable()
				repo.webhooks[w.ID()] = w
				repo.updateErr = fmt.Errorf("update failed")
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := newMockWebhookRepo()
			enc := newMockWebhookEncryptor()
			if tc.setupRepo != nil {
				tc.setupRepo(repo)
			}

			svc := newTestWebhookService(repo, enc)
			result, err := svc.EnableWebhook(context.Background(), tc.id, tc.tenantIDStr)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.errIs != nil && !errors.Is(err, tc.errIs) {
					t.Errorf("expected error wrapping %v, got %v", tc.errIs, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("expected non-nil webhook")
			}

			if tc.validate != nil {
				tc.validate(t, result, repo)
			}
		})
	}
}

// =============================================================================
// Test: DisableWebhook
// =============================================================================

func TestWebhookService_DisableWebhook(t *testing.T) {
	tenantID := shared.NewID()
	webhookID := shared.NewID()

	tests := []struct {
		name        string
		id          string
		tenantIDStr string
		setupRepo   func(*mockWebhookRepo)
		wantErr     bool
		errIs       error
		validate    func(t *testing.T, w *webhook.Webhook, repo *mockWebhookRepo)
	}{
		{
			name:        "success - disable active webhook",
			id:          webhookID.String(),
			tenantIDStr: tenantID.String(),
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Active Hook", "https://example.com/hook", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
			},
			wantErr: false,
			validate: func(t *testing.T, w *webhook.Webhook, repo *mockWebhookRepo) {
				if w.Status() != webhook.StatusDisabled {
					t.Errorf("expected status disabled, got %s", w.Status())
				}
				if repo.updateCalls != 1 {
					t.Errorf("expected 1 update call, got %d", repo.updateCalls)
				}
			},
		},
		{
			name:        "success - disable already disabled webhook (idempotent)",
			id:          webhookID.String(),
			tenantIDStr: tenantID.String(),
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Disabled Hook", "https://example.com/hook", []string{"finding.created"})
				w.Disable()
				repo.webhooks[w.ID()] = w
			},
			wantErr: false,
			validate: func(t *testing.T, w *webhook.Webhook, repo *mockWebhookRepo) {
				if w.Status() != webhook.StatusDisabled {
					t.Errorf("expected status disabled, got %s", w.Status())
				}
			},
		},
		{
			name:        "error - invalid webhook ID",
			id:          "bad",
			tenantIDStr: tenantID.String(),
			wantErr:     true,
			errIs:       shared.ErrValidation,
		},
		{
			name:        "error - invalid tenant ID",
			id:          webhookID.String(),
			tenantIDStr: "bad",
			wantErr:     true,
			errIs:       shared.ErrValidation,
		},
		{
			name:        "error - webhook not found",
			id:          shared.NewID().String(),
			tenantIDStr: tenantID.String(),
			wantErr:     true,
			errIs:       shared.ErrNotFound,
		},
		{
			name:        "error - cross-tenant disable rejected",
			id:          webhookID.String(),
			tenantIDStr: shared.NewID().String(),
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Hook", "https://example.com/hook", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
			},
			wantErr: true,
			errIs:   shared.ErrNotFound,
		},
		{
			name:        "error - repository update failure",
			id:          webhookID.String(),
			tenantIDStr: tenantID.String(),
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Hook", "https://example.com/hook", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
				repo.updateErr = fmt.Errorf("update failed")
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := newMockWebhookRepo()
			enc := newMockWebhookEncryptor()
			if tc.setupRepo != nil {
				tc.setupRepo(repo)
			}

			svc := newTestWebhookService(repo, enc)
			result, err := svc.DisableWebhook(context.Background(), tc.id, tc.tenantIDStr)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.errIs != nil && !errors.Is(err, tc.errIs) {
					t.Errorf("expected error wrapping %v, got %v", tc.errIs, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("expected non-nil webhook")
			}

			if tc.validate != nil {
				tc.validate(t, result, repo)
			}
		})
	}
}

// =============================================================================
// Test: DeleteWebhook
// =============================================================================

func TestWebhookService_DeleteWebhook(t *testing.T) {
	tenantID := shared.NewID()
	webhookID := shared.NewID()

	tests := []struct {
		name        string
		id          string
		tenantIDStr string
		setupRepo   func(*mockWebhookRepo)
		wantErr     bool
		errIs       error
		validate    func(t *testing.T, repo *mockWebhookRepo)
	}{
		{
			name:        "success - delete existing webhook",
			id:          webhookID.String(),
			tenantIDStr: tenantID.String(),
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "To Delete", "https://example.com/hook", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
			},
			wantErr: false,
			validate: func(t *testing.T, repo *mockWebhookRepo) {
				if repo.deleteCalls != 1 {
					t.Errorf("expected 1 delete call, got %d", repo.deleteCalls)
				}
				if len(repo.webhooks) != 0 {
					t.Errorf("expected 0 webhooks remaining, got %d", len(repo.webhooks))
				}
			},
		},
		{
			name:        "error - invalid webhook ID",
			id:          "bad-id",
			tenantIDStr: tenantID.String(),
			wantErr:     true,
			errIs:       shared.ErrValidation,
		},
		{
			name:        "error - invalid tenant ID",
			id:          webhookID.String(),
			tenantIDStr: "bad-tenant",
			wantErr:     true,
			errIs:       shared.ErrValidation,
		},
		{
			name:        "error - webhook not found",
			id:          shared.NewID().String(),
			tenantIDStr: tenantID.String(),
			wantErr:     true,
			errIs:       shared.ErrNotFound,
		},
		{
			name:        "error - cross-tenant delete rejected",
			id:          webhookID.String(),
			tenantIDStr: shared.NewID().String(),
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Protected", "https://example.com/hook", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
			},
			wantErr: true,
			errIs:   shared.ErrNotFound,
		},
		{
			name:        "error - repository delete failure",
			id:          webhookID.String(),
			tenantIDStr: tenantID.String(),
			setupRepo: func(repo *mockWebhookRepo) {
				repo.deleteErr = fmt.Errorf("db error")
			},
			wantErr: true,
		},
		{
			name:        "success - passes correct IDs to repo",
			id:          webhookID.String(),
			tenantIDStr: tenantID.String(),
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Check IDs", "https://example.com/hook", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
			},
			wantErr: false,
			validate: func(t *testing.T, repo *mockWebhookRepo) {
				if repo.lastDeleteID != webhookID {
					t.Errorf("expected delete ID %s, got %s", webhookID, repo.lastDeleteID)
				}
				if repo.lastDeleteTenantID != tenantID {
					t.Errorf("expected delete tenant ID %s, got %s", tenantID, repo.lastDeleteTenantID)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := newMockWebhookRepo()
			enc := newMockWebhookEncryptor()
			if tc.setupRepo != nil {
				tc.setupRepo(repo)
			}

			svc := newTestWebhookService(repo, enc)
			err := svc.DeleteWebhook(context.Background(), tc.id, tc.tenantIDStr)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.errIs != nil && !errors.Is(err, tc.errIs) {
					t.Errorf("expected error wrapping %v, got %v", tc.errIs, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.validate != nil {
				tc.validate(t, repo)
			}
		})
	}
}

// =============================================================================
// Test: ListDeliveries
// =============================================================================

func TestWebhookService_ListDeliveries(t *testing.T) {
	tenantID := shared.NewID()
	webhookID := shared.NewID()

	tests := []struct {
		name      string
		input     app.ListDeliveriesInput
		setupRepo func(*mockWebhookRepo)
		wantErr   bool
		errIs     error
		validate  func(t *testing.T, result webhook.DeliveryListResult, repo *mockWebhookRepo)
	}{
		{
			name: "success - list deliveries for valid webhook",
			input: app.ListDeliveriesInput{
				WebhookID: webhookID.String(),
				TenantID:  tenantID.String(),
				Page:      1,
				PerPage:   20,
			},
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Hook", "https://example.com/hook", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
			},
			wantErr: false,
			validate: func(t *testing.T, result webhook.DeliveryListResult, repo *mockWebhookRepo) {
				if repo.getByIDCalls != 1 {
					t.Errorf("expected 1 getByID call (ownership check), got %d", repo.getByIDCalls)
				}
				if repo.listDeliveriesCalls != 1 {
					t.Errorf("expected 1 listDeliveries call, got %d", repo.listDeliveriesCalls)
				}
			},
		},
		{
			name: "success - passes status filter",
			input: app.ListDeliveriesInput{
				WebhookID: webhookID.String(),
				TenantID:  tenantID.String(),
				Status:    "success",
				Page:      1,
				PerPage:   10,
			},
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Hook", "https://example.com/hook", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
			},
			wantErr: false,
			validate: func(t *testing.T, result webhook.DeliveryListResult, repo *mockWebhookRepo) {
				f := repo.lastDeliveryFilter
				if f.Status == nil {
					t.Fatal("expected status filter to be set")
				}
				if *f.Status != webhook.DeliverySuccess {
					t.Errorf("expected status filter 'success', got %s", *f.Status)
				}
			},
		},
		{
			name: "success - no status filter when empty",
			input: app.ListDeliveriesInput{
				WebhookID: webhookID.String(),
				TenantID:  tenantID.String(),
			},
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Hook", "https://example.com/hook", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
			},
			wantErr: false,
			validate: func(t *testing.T, result webhook.DeliveryListResult, repo *mockWebhookRepo) {
				f := repo.lastDeliveryFilter
				if f.Status != nil {
					t.Error("expected status filter to be nil")
				}
			},
		},
		{
			name: "error - invalid webhook ID",
			input: app.ListDeliveriesInput{
				WebhookID: "not-uuid",
				TenantID:  tenantID.String(),
			},
			wantErr: true,
			errIs:   shared.ErrValidation,
		},
		{
			name: "error - invalid tenant ID",
			input: app.ListDeliveriesInput{
				WebhookID: webhookID.String(),
				TenantID:  "not-uuid",
			},
			wantErr: true,
			errIs:   shared.ErrValidation,
		},
		{
			name: "error - webhook not found (ownership check fails)",
			input: app.ListDeliveriesInput{
				WebhookID: shared.NewID().String(),
				TenantID:  tenantID.String(),
			},
			wantErr: true,
			errIs:   shared.ErrNotFound,
		},
		{
			name: "error - cross-tenant delivery listing rejected",
			input: app.ListDeliveriesInput{
				WebhookID: webhookID.String(),
				TenantID:  shared.NewID().String(),
			},
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Hook", "https://example.com/hook", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
			},
			wantErr: true,
			errIs:   shared.ErrNotFound,
		},
		{
			name: "error - repository listDeliveries failure",
			input: app.ListDeliveriesInput{
				WebhookID: webhookID.String(),
				TenantID:  tenantID.String(),
			},
			setupRepo: func(repo *mockWebhookRepo) {
				w := webhook.NewWebhook(webhookID, tenantID, "Hook", "https://example.com/hook", []string{"finding.created"})
				repo.webhooks[w.ID()] = w
				repo.listDeliveriesErr = fmt.Errorf("db error")
			},
			wantErr: true,
		},
		{
			name: "error - repository getByID failure during ownership check",
			input: app.ListDeliveriesInput{
				WebhookID: webhookID.String(),
				TenantID:  tenantID.String(),
			},
			setupRepo: func(repo *mockWebhookRepo) {
				repo.getByIDErr = fmt.Errorf("db connection error")
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := newMockWebhookRepo()
			enc := newMockWebhookEncryptor()
			if tc.setupRepo != nil {
				tc.setupRepo(repo)
			}

			svc := newTestWebhookService(repo, enc)
			result, err := svc.ListDeliveries(context.Background(), tc.input)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.errIs != nil && !errors.Is(err, tc.errIs) {
					t.Errorf("expected error wrapping %v, got %v", tc.errIs, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.validate != nil {
				tc.validate(t, result, repo)
			}
		})
	}
}

// =============================================================================
// Test: NewWebhookService with nil encryptor
// =============================================================================

func TestNewWebhookService_NilEncryptor(t *testing.T) {
	repo := newMockWebhookRepo()
	log := logger.NewNop()

	// Should not panic - uses NoOpEncryptor as fallback
	svc := app.NewWebhookService(repo, nil, log)
	if svc == nil {
		t.Fatal("expected non-nil service")
	}

	// Verify it works by creating a webhook with a secret
	tenantID := shared.NewID()
	result, err := svc.CreateWebhook(context.Background(), app.CreateWebhookInput{
		TenantID:   tenantID.String(),
		Name:       "NoOp Encrypted Hook",
		URL:        "https://example.com/hook",
		Secret:     "plain-secret",
		EventTypes: []string{"finding.created"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With NoOpEncryptor, secret is stored as-is
	if string(result.SecretEncrypted()) != "plain-secret" {
		t.Errorf("expected secret 'plain-secret' with NoOp, got %q", string(result.SecretEncrypted()))
	}
}

// =============================================================================
// Test: Cross-Tenant Isolation (comprehensive)
// =============================================================================

func TestWebhookService_CrossTenantIsolation(t *testing.T) {
	tenantA := shared.NewID()
	tenantB := shared.NewID()
	webhookID := shared.NewID()

	repo := newMockWebhookRepo()
	enc := newMockWebhookEncryptor()
	svc := newTestWebhookService(repo, enc)

	// Create webhook for tenant A
	w := webhook.NewWebhook(webhookID, tenantA, "Tenant A Hook", "https://example.com/hook", []string{"finding.created"})
	repo.webhooks[w.ID()] = w

	t.Run("GetWebhook - tenant B cannot access tenant A webhook", func(t *testing.T) {
		_, err := svc.GetWebhook(context.Background(), webhookID.String(), tenantB.String())
		if err == nil {
			t.Fatal("expected error for cross-tenant access")
		}
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("UpdateWebhook - tenant B cannot update tenant A webhook", func(t *testing.T) {
		name := "Hacked"
		_, err := svc.UpdateWebhook(context.Background(), webhookID.String(), tenantB.String(), app.UpdateWebhookInput{
			Name: &name,
		})
		if err == nil {
			t.Fatal("expected error for cross-tenant update")
		}
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("EnableWebhook - tenant B cannot enable tenant A webhook", func(t *testing.T) {
		_, err := svc.EnableWebhook(context.Background(), webhookID.String(), tenantB.String())
		if err == nil {
			t.Fatal("expected error for cross-tenant enable")
		}
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("DisableWebhook - tenant B cannot disable tenant A webhook", func(t *testing.T) {
		_, err := svc.DisableWebhook(context.Background(), webhookID.String(), tenantB.String())
		if err == nil {
			t.Fatal("expected error for cross-tenant disable")
		}
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("DeleteWebhook - tenant B cannot delete tenant A webhook", func(t *testing.T) {
		err := svc.DeleteWebhook(context.Background(), webhookID.String(), tenantB.String())
		if err == nil {
			t.Fatal("expected error for cross-tenant delete")
		}
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("ListDeliveries - tenant B cannot list tenant A webhook deliveries", func(t *testing.T) {
		_, err := svc.ListDeliveries(context.Background(), app.ListDeliveriesInput{
			WebhookID: webhookID.String(),
			TenantID:  tenantB.String(),
		})
		if err == nil {
			t.Fatal("expected error for cross-tenant delivery listing")
		}
		if !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	// Verify original webhook is untouched
	t.Run("verify webhook unchanged after cross-tenant attempts", func(t *testing.T) {
		got, err := svc.GetWebhook(context.Background(), webhookID.String(), tenantA.String())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Name() != "Tenant A Hook" {
			t.Errorf("webhook name was modified: got %q", got.Name())
		}
		if got.Status() != webhook.StatusActive {
			t.Errorf("webhook status was modified: got %s", got.Status())
		}
	})
}

// =============================================================================
// Test: URL Validation Edge Cases
// =============================================================================

func TestWebhookService_URLValidation(t *testing.T) {
	tenantID := shared.NewID()

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"valid HTTPS URL", "https://hooks.slack.com/services/xxx", false},
		{"valid HTTP URL", "http://webhook.site/abc123", false},
		{"localhost rejected", "https://localhost/hook", true},
		{"127.0.0.1 rejected", "http://127.0.0.1:8080/hook", true},
		{"0.0.0.0 rejected", "http://0.0.0.0/hook", true},
		{"::1 rejected", "http://[::1]:8080/hook", true},
		{"10.x.x.x rejected", "http://10.0.0.1/hook", true},
		{"172.16.x.x rejected", "http://172.16.0.1/hook", true},
		{"192.168.x.x rejected", "http://192.168.1.100/hook", true},
		{"cloud metadata rejected", "http://169.254.169.254/latest", true},
		{"GCP metadata rejected", "http://metadata.google.internal/v1/", true},
		{"FTP scheme rejected", "ftp://example.com/file", true},
		{"file scheme rejected", "file:///etc/passwd", true},
		{"empty hostname rejected", "http:///path", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := newMockWebhookRepo()
			enc := newMockWebhookEncryptor()
			svc := newTestWebhookService(repo, enc)

			_, err := svc.CreateWebhook(context.Background(), app.CreateWebhookInput{
				TenantID:   tenantID.String(),
				Name:       "URL Test - " + tc.name,
				URL:        tc.url,
				EventTypes: []string{"finding.created"},
			})

			if tc.wantErr && err == nil {
				t.Errorf("expected error for URL %q, got nil", tc.url)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for URL %q: %v", tc.url, err)
			}
		})
	}
}
