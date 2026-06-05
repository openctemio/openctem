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
