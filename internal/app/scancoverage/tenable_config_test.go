package scancoverage

import "testing"

func TestParseTenableConfig_Defaults(t *testing.T) {
	c, err := ParseTenableConfig(nil)
	if err != nil {
		t.Fatalf("nil config should default cleanly: %v", err)
	}
	if c.ExecutionMode != ExecutionModeAgent || c.Engine != EngineNessusPro {
		t.Fatalf("defaults should be agent + nessus_pro, got %+v", c)
	}
}

func TestParseTenableConfig_Valid(t *testing.T) {
	c, err := ParseTenableConfig(map[string]any{"execution_mode": "Direct", "engine": "TENABLE_SC"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.ExecutionMode != ExecutionModeDirect || c.Engine != EngineTenableSC {
		t.Fatalf("case-insensitive parse failed: %+v", c)
	}
}

func TestParseTenableConfig_Invalid(t *testing.T) {
	if _, err := ParseTenableConfig(map[string]any{"execution_mode": "pull"}); err == nil {
		t.Fatal("invalid execution_mode must error")
	}
	if _, err := ParseTenableConfig(map[string]any{"engine": "openvas"}); err == nil {
		t.Fatal("invalid engine must error")
	}
}

func TestValidate_AgentModeRejectsCredentials(t *testing.T) {
	cfg := TenableConfig{ExecutionMode: ExecutionModeAgent, Engine: EngineTenableSC}
	if err := ValidateTenableIntegration(cfg, true, ""); err == nil {
		t.Fatal("agent mode must reject control-plane credentials (R3/R4)")
	}
	if err := ValidateTenableIntegration(cfg, false, ""); err != nil {
		t.Fatalf("agent mode without creds is valid: %v", err)
	}
}

func TestValidate_DirectModeRequiresCredsAndURL(t *testing.T) {
	cfg := TenableConfig{ExecutionMode: ExecutionModeDirect, Engine: EngineNessusPro}
	if err := ValidateTenableIntegration(cfg, false, "https://t"); err == nil {
		t.Fatal("direct mode requires credentials")
	}
	if err := ValidateTenableIntegration(cfg, true, ""); err == nil {
		t.Fatal("direct mode requires base_url")
	}
	if err := ValidateTenableIntegration(cfg, true, "https://acme.tenable.io"); err != nil {
		t.Fatalf("direct mode with creds + url is valid: %v", err)
	}
}

func TestParseTenableConfig_CoverageFields(t *testing.T) {
	// JSON numbers decode to float64 — exercise that path plus a numeric string.
	c, err := ParseTenableConfig(map[string]any{
		"coverage_enabled": true,
		"batch_size":       float64(500),
		"license_cap":      "500",
		"safety_margin":    float64(10),
		"agent_id":         "  agent-123  ",
		"template_uuid":    " tmpl-xyz ",
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !c.CoverageEnabled {
		t.Fatal("coverage_enabled should be true")
	}
	if c.BatchSize != 500 || c.LicenseCap != 500 || c.SafetyMargin != 10 {
		t.Fatalf("numeric fields wrong: %+v", c)
	}
	if c.AgentID != "agent-123" || c.TemplateUUID != "tmpl-xyz" {
		t.Fatalf("string fields should be trimmed: %+v", c)
	}
}

func TestParseTenableConfig_RejectsNegativeNumbers(t *testing.T) {
	if _, err := ParseTenableConfig(map[string]any{"batch_size": float64(-1)}); err == nil {
		t.Fatal("negative batch_size must be rejected")
	}
}

func TestTenableConfig_LicensePolicy(t *testing.T) {
	pro := TenableConfig{Engine: EngineNessusPro}.LicensePolicy()
	if pro.Mode != LicenseUnlimited {
		t.Fatalf("nessus pro must be unlimited, got %v", pro.Mode)
	}
	sc := TenableConfig{Engine: EngineTenableSC, LicenseCap: 500, SafetyMargin: 10}.LicensePolicy()
	if sc.Mode != LicenseActiveIPCap || sc.Cap != 500 || sc.SafetyMargin != 10 {
		t.Fatalf(".sc policy wrong: %+v", sc)
	}
}

func TestTenableConfig_EffectiveBatchSize(t *testing.T) {
	if got := (TenableConfig{}).EffectiveBatchSize(); got != DefaultCoverageBatch {
		t.Fatalf("zero batch should default to %d, got %d", DefaultCoverageBatch, got)
	}
	if got := (TenableConfig{BatchSize: 42}).EffectiveBatchSize(); got != 42 {
		t.Fatalf("explicit batch should be used, got %d", got)
	}
}
