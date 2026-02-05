package validator

import (
	"testing"
)

func TestNew(t *testing.T) {
	v := New()
	if v == nil {
		t.Fatal("expected validator to be created")
	}
	if v.validate == nil {
		t.Fatal("expected internal validator to be initialized")
	}
}

func TestValidate_RequiredField(t *testing.T) {
	v := New()

	type TestStruct struct {
		Name string `validate:"required"`
	}

	tests := []struct {
		name    string
		input   TestStruct
		wantErr bool
	}{
		{
			name:    "valid - name provided",
			input:   TestStruct{Name: "test"},
			wantErr: false,
		},
		{
			name:    "invalid - name empty",
			input:   TestStruct{Name: ""},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAssetType(t *testing.T) {
	v := New()

	type TestStruct struct {
		Type string `validate:"required,asset_type"`
	}

	tests := []struct {
		name    string
		input   TestStruct
		wantErr bool
	}{
		{name: "valid - repository", input: TestStruct{Type: "repository"}, wantErr: false},
		{name: "valid - server", input: TestStruct{Type: "server"}, wantErr: false},
		{name: "valid - container", input: TestStruct{Type: "container"}, wantErr: false},
		{name: "valid - cloud_account", input: TestStruct{Type: "cloud_account"}, wantErr: false},
		{name: "valid - network", input: TestStruct{Type: "network"}, wantErr: false},
		{name: "valid - web_application", input: TestStruct{Type: "web_application"}, wantErr: false},
		{name: "valid - database", input: TestStruct{Type: "database"}, wantErr: false},
		{name: "valid - api", input: TestStruct{Type: "api"}, wantErr: false},
		{name: "valid - domain", input: TestStruct{Type: "domain"}, wantErr: false},
		{name: "valid - host", input: TestStruct{Type: "host"}, wantErr: false},
		{name: "invalid - unknown type", input: TestStruct{Type: "invalid_type"}, wantErr: true},
		{name: "invalid - empty", input: TestStruct{Type: ""}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateCriticality(t *testing.T) {
	v := New()

	type TestStruct struct {
		Criticality string `validate:"required,criticality"`
	}

	tests := []struct {
		name    string
		input   TestStruct
		wantErr bool
	}{
		{name: "valid - critical", input: TestStruct{Criticality: "critical"}, wantErr: false},
		{name: "valid - high", input: TestStruct{Criticality: "high"}, wantErr: false},
		{name: "valid - medium", input: TestStruct{Criticality: "medium"}, wantErr: false},
		{name: "valid - low", input: TestStruct{Criticality: "low"}, wantErr: false},
		{name: "valid - none", input: TestStruct{Criticality: "none"}, wantErr: false},
		{name: "invalid - unknown", input: TestStruct{Criticality: "unknown"}, wantErr: true},
		{name: "invalid - empty", input: TestStruct{Criticality: ""}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateStatus(t *testing.T) {
	v := New()

	type TestStruct struct {
		Status string `validate:"required,status"`
	}

	tests := []struct {
		name    string
		input   TestStruct
		wantErr bool
	}{
		{name: "valid - active", input: TestStruct{Status: "active"}, wantErr: false},
		{name: "valid - inactive", input: TestStruct{Status: "inactive"}, wantErr: false},
		{name: "valid - archived", input: TestStruct{Status: "archived"}, wantErr: false},
		{name: "invalid - unknown", input: TestStruct{Status: "unknown"}, wantErr: true},
		{name: "invalid - empty", input: TestStruct{Status: ""}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateScope(t *testing.T) {
	v := New()

	type TestStruct struct {
		Scope string `validate:"omitempty,scope"`
	}

	tests := []struct {
		name    string
		input   TestStruct
		wantErr bool
	}{
		{name: "valid - internal", input: TestStruct{Scope: "internal"}, wantErr: false},
		{name: "valid - external", input: TestStruct{Scope: "external"}, wantErr: false},
		{name: "valid - cloud", input: TestStruct{Scope: "cloud"}, wantErr: false},
		{name: "valid - empty (omitempty)", input: TestStruct{Scope: ""}, wantErr: false},
		{name: "invalid - unknown", input: TestStruct{Scope: "unknown_scope"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateExposure(t *testing.T) {
	v := New()

	type TestStruct struct {
		Exposure string `validate:"omitempty,exposure"`
	}

	tests := []struct {
		name    string
		input   TestStruct
		wantErr bool
	}{
		{name: "valid - public", input: TestStruct{Exposure: "public"}, wantErr: false},
		{name: "valid - private", input: TestStruct{Exposure: "private"}, wantErr: false},
		{name: "valid - restricted", input: TestStruct{Exposure: "restricted"}, wantErr: false},
		{name: "valid - empty (omitempty)", input: TestStruct{Exposure: ""}, wantErr: false},
		{name: "invalid - invalid_exposure", input: TestStruct{Exposure: "invalid_exposure"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSeverity(t *testing.T) {
	v := New()

	type TestStruct struct {
		Severity string `validate:"required,severity"`
	}

	tests := []struct {
		name    string
		input   TestStruct
		wantErr bool
	}{
		{name: "valid - critical", input: TestStruct{Severity: "critical"}, wantErr: false},
		{name: "valid - high", input: TestStruct{Severity: "high"}, wantErr: false},
		{name: "valid - medium", input: TestStruct{Severity: "medium"}, wantErr: false},
		{name: "valid - low", input: TestStruct{Severity: "low"}, wantErr: false},
		{name: "valid - none", input: TestStruct{Severity: "none"}, wantErr: false},
		{name: "invalid - unknown", input: TestStruct{Severity: "unknown"}, wantErr: true},
		{name: "invalid - empty", input: TestStruct{Severity: ""}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateFindingStatus(t *testing.T) {
	v := New()

	type TestStruct struct {
		Status string `validate:"required,finding_status"`
	}

	tests := []struct {
		name    string
		input   TestStruct
		wantErr bool
	}{
		{name: "valid - new", input: TestStruct{Status: "new"}, wantErr: false},
		{name: "valid - confirmed", input: TestStruct{Status: "confirmed"}, wantErr: false},
		{name: "valid - in_progress", input: TestStruct{Status: "in_progress"}, wantErr: false},
		{name: "valid - resolved", input: TestStruct{Status: "resolved"}, wantErr: false},
		{name: "valid - false_positive", input: TestStruct{Status: "false_positive"}, wantErr: false},
		{name: "valid - accepted", input: TestStruct{Status: "accepted"}, wantErr: false},
		{name: "valid - duplicate", input: TestStruct{Status: "duplicate"}, wantErr: false},
		{name: "invalid - unknown", input: TestStruct{Status: "unknown"}, wantErr: true},
		{name: "invalid - empty", input: TestStruct{Status: ""}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateFindingSource(t *testing.T) {
	v := New()

	type TestStruct struct {
		Source string `validate:"required,finding_source"`
	}

	tests := []struct {
		name    string
		input   TestStruct
		wantErr bool
	}{
		{name: "valid - sast", input: TestStruct{Source: "sast"}, wantErr: false},
		{name: "valid - dast", input: TestStruct{Source: "dast"}, wantErr: false},
		{name: "valid - sca", input: TestStruct{Source: "sca"}, wantErr: false},
		{name: "valid - secret", input: TestStruct{Source: "secret"}, wantErr: false},
		{name: "valid - iac", input: TestStruct{Source: "iac"}, wantErr: false},
		{name: "valid - container", input: TestStruct{Source: "container"}, wantErr: false},
		{name: "valid - manual", input: TestStruct{Source: "manual"}, wantErr: false},
		{name: "invalid - unknown", input: TestStruct{Source: "unknown"}, wantErr: true},
		{name: "invalid - empty", input: TestStruct{Source: ""}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateExploitMaturity(t *testing.T) {
	v := New()

	type TestStruct struct {
		Maturity string `validate:"omitempty,exploit_maturity"`
	}

	tests := []struct {
		name    string
		input   TestStruct
		wantErr bool
	}{
		{name: "valid - none", input: TestStruct{Maturity: "none"}, wantErr: false},
		{name: "valid - poc", input: TestStruct{Maturity: "poc"}, wantErr: false},
		{name: "valid - functional", input: TestStruct{Maturity: "functional"}, wantErr: false},
		{name: "valid - weaponized", input: TestStruct{Maturity: "weaponized"}, wantErr: false},
		{name: "valid - empty (omitempty)", input: TestStruct{Maturity: ""}, wantErr: false},
		{name: "invalid - unknown", input: TestStruct{Maturity: "unknown"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateVulnerabilityStatus(t *testing.T) {
	v := New()

	type TestStruct struct {
		Status string `validate:"omitempty,vulnerability_status"`
	}

	tests := []struct {
		name    string
		input   TestStruct
		wantErr bool
	}{
		{name: "valid - open", input: TestStruct{Status: "open"}, wantErr: false},
		{name: "valid - patched", input: TestStruct{Status: "patched"}, wantErr: false},
		{name: "valid - mitigated", input: TestStruct{Status: "mitigated"}, wantErr: false},
		{name: "valid - not_affected", input: TestStruct{Status: "not_affected"}, wantErr: false},
		{name: "valid - empty (omitempty)", input: TestStruct{Status: ""}, wantErr: false},
		{name: "invalid - unknown", input: TestStruct{Status: "unknown"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateCVEID(t *testing.T) {
	v := New()

	type TestStruct struct {
		CVEID string `validate:"required,cve_id"`
	}

	tests := []struct {
		name    string
		input   TestStruct
		wantErr bool
	}{
		{name: "valid - CVE-2024-12345", input: TestStruct{CVEID: "CVE-2024-12345"}, wantErr: false},
		{name: "valid - CVE-2023-1234", input: TestStruct{CVEID: "CVE-2023-1234"}, wantErr: false},
		{name: "valid - CVE-2024-123456", input: TestStruct{CVEID: "CVE-2024-123456"}, wantErr: false},
		{name: "valid - lowercase", input: TestStruct{CVEID: "cve-2024-12345"}, wantErr: false},
		{name: "invalid - missing CVE prefix", input: TestStruct{CVEID: "2024-12345"}, wantErr: true},
		{name: "invalid - wrong format", input: TestStruct{CVEID: "CVE-24-12345"}, wantErr: true},
		{name: "invalid - too few digits", input: TestStruct{CVEID: "CVE-2024-123"}, wantErr: true},
		{name: "invalid - empty", input: TestStruct{CVEID: ""}, wantErr: true},
		{name: "invalid - random string", input: TestStruct{CVEID: "not-a-cve"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateEcosystem(t *testing.T) {
	v := New()

	type TestStruct struct {
		Ecosystem string `validate:"required,ecosystem"`
	}

	tests := []struct {
		name    string
		input   TestStruct
		wantErr bool
	}{
		{name: "valid - npm", input: TestStruct{Ecosystem: "npm"}, wantErr: false},
		{name: "valid - pypi", input: TestStruct{Ecosystem: "pypi"}, wantErr: false},
		{name: "valid - maven", input: TestStruct{Ecosystem: "maven"}, wantErr: false},
		{name: "valid - nuget", input: TestStruct{Ecosystem: "nuget"}, wantErr: false},
		{name: "valid - go", input: TestStruct{Ecosystem: "go"}, wantErr: false},
		{name: "valid - cargo", input: TestStruct{Ecosystem: "cargo"}, wantErr: false},
		{name: "valid - rubygems", input: TestStruct{Ecosystem: "rubygems"}, wantErr: false},
		{name: "valid - composer", input: TestStruct{Ecosystem: "composer"}, wantErr: false},
		// Note: ParseEcosystem defaults to "other" for unknown ecosystems (no error)
		{name: "valid - unknown defaults to other", input: TestStruct{Ecosystem: "unknown"}, wantErr: false},
		{name: "invalid - empty", input: TestStruct{Ecosystem: ""}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateDependencyType(t *testing.T) {
	v := New()

	type TestStruct struct {
		Type string `validate:"omitempty,dependency_type"`
	}

	tests := []struct {
		name    string
		input   TestStruct
		wantErr bool
	}{
		{name: "valid - direct", input: TestStruct{Type: "direct"}, wantErr: false},
		{name: "valid - transitive", input: TestStruct{Type: "transitive"}, wantErr: false},
		{name: "valid - dev", input: TestStruct{Type: "dev"}, wantErr: false},
		{name: "valid - optional", input: TestStruct{Type: "optional"}, wantErr: false},
		{name: "valid - empty (omitempty)", input: TestStruct{Type: ""}, wantErr: false},
		// Note: ParseDependencyType defaults to "direct" for unknown types (no error)
		{name: "valid - unknown defaults to direct", input: TestStruct{Type: "unknown"}, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateComponentStatus(t *testing.T) {
	v := New()

	type TestStruct struct {
		Status string `validate:"omitempty,component_status"`
	}

	tests := []struct {
		name    string
		input   TestStruct
		wantErr bool
	}{
		{name: "valid - active", input: TestStruct{Status: "active"}, wantErr: false},
		{name: "valid - deprecated", input: TestStruct{Status: "deprecated"}, wantErr: false},
		{name: "valid - end_of_life", input: TestStruct{Status: "end_of_life"}, wantErr: false},
		{name: "valid - unknown", input: TestStruct{Status: "unknown"}, wantErr: false},
		{name: "valid - empty (omitempty)", input: TestStruct{Status: ""}, wantErr: false},
		{name: "invalid - invalid_status", input: TestStruct{Status: "invalid_status"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateBranchType(t *testing.T) {
	v := New()

	type TestStruct struct {
		Type string `validate:"omitempty,branch_type"`
	}

	tests := []struct {
		name    string
		input   TestStruct
		wantErr bool
	}{
		{name: "valid - main", input: TestStruct{Type: "main"}, wantErr: false},
		{name: "valid - feature", input: TestStruct{Type: "feature"}, wantErr: false},
		{name: "valid - release", input: TestStruct{Type: "release"}, wantErr: false},
		{name: "valid - hotfix", input: TestStruct{Type: "hotfix"}, wantErr: false},
		{name: "valid - develop", input: TestStruct{Type: "develop"}, wantErr: false},
		{name: "valid - empty (omitempty)", input: TestStruct{Type: ""}, wantErr: false},
		// Note: ParseType defaults to "other" for unknown types (no error)
		{name: "valid - unknown defaults to other", input: TestStruct{Type: "unknown"}, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateScanStatus(t *testing.T) {
	v := New()

	type TestStruct struct {
		Status string `validate:"omitempty,scan_status"`
	}

	tests := []struct {
		name    string
		input   TestStruct
		wantErr bool
	}{
		{name: "valid - passed", input: TestStruct{Status: "passed"}, wantErr: false},
		{name: "valid - failed", input: TestStruct{Status: "failed"}, wantErr: false},
		{name: "valid - warning", input: TestStruct{Status: "warning"}, wantErr: false},
		{name: "valid - scanning", input: TestStruct{Status: "scanning"}, wantErr: false},
		{name: "valid - empty (omitempty)", input: TestStruct{Status: ""}, wantErr: false},
		// Note: ParseScanStatus defaults to "not_scanned" for unknown (no error)
		{name: "valid - unknown defaults to not_scanned", input: TestStruct{Status: "unknown"}, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateQualityGateStatus(t *testing.T) {
	v := New()

	type TestStruct struct {
		Status string `validate:"omitempty,quality_gate_status"`
	}

	tests := []struct {
		name    string
		input   TestStruct
		wantErr bool
	}{
		{name: "valid - passed", input: TestStruct{Status: "passed"}, wantErr: false},
		{name: "valid - failed", input: TestStruct{Status: "failed"}, wantErr: false},
		{name: "valid - warning", input: TestStruct{Status: "warning"}, wantErr: false},
		{name: "valid - not_computed", input: TestStruct{Status: "not_computed"}, wantErr: false},
		{name: "valid - empty (omitempty)", input: TestStruct{Status: ""}, wantErr: false},
		// Note: ParseQualityGateStatus defaults to "not_computed" for unknown (no error)
		{name: "valid - unknown defaults to not_computed", input: TestStruct{Status: "unknown"}, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSlug(t *testing.T) {
	v := New()

	type TestStruct struct {
		Slug string `validate:"required,slug"`
	}

	tests := []struct {
		name    string
		input   TestStruct
		wantErr bool
	}{
		{name: "valid - simple", input: TestStruct{Slug: "my-team"}, wantErr: false},
		{name: "valid - with numbers", input: TestStruct{Slug: "team123"}, wantErr: false},
		{name: "valid - lowercase", input: TestStruct{Slug: "acme-corp"}, wantErr: false},
		{name: "valid - single word", input: TestStruct{Slug: "team"}, wantErr: false},
		{name: "invalid - uppercase", input: TestStruct{Slug: "My-Team"}, wantErr: true},
		{name: "invalid - spaces", input: TestStruct{Slug: "my team"}, wantErr: true},
		{name: "invalid - special chars", input: TestStruct{Slug: "my_team"}, wantErr: true},
		{name: "invalid - starts with hyphen", input: TestStruct{Slug: "-team"}, wantErr: true},
		{name: "invalid - ends with hyphen", input: TestStruct{Slug: "team-"}, wantErr: true},
		{name: "invalid - empty", input: TestStruct{Slug: ""}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSCMProvider(t *testing.T) {
	v := New()

	type TestStruct struct {
		Provider string `validate:"omitempty,scm_provider"`
	}

	tests := []struct {
		name    string
		input   TestStruct
		wantErr bool
	}{
		{name: "valid - github", input: TestStruct{Provider: "github"}, wantErr: false},
		{name: "valid - gitlab", input: TestStruct{Provider: "gitlab"}, wantErr: false},
		{name: "valid - bitbucket", input: TestStruct{Provider: "bitbucket"}, wantErr: false},
		{name: "valid - azure_devops", input: TestStruct{Provider: "azure_devops"}, wantErr: false},
		{name: "valid - empty (omitempty)", input: TestStruct{Provider: ""}, wantErr: false},
		{name: "invalid - unknown", input: TestStruct{Provider: "unknown"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateRepoVisibility(t *testing.T) {
	v := New()

	type TestStruct struct {
		Visibility string `validate:"omitempty,repo_visibility"`
	}

	tests := []struct {
		name    string
		input   TestStruct
		wantErr bool
	}{
		{name: "valid - public", input: TestStruct{Visibility: "public"}, wantErr: false},
		{name: "valid - private", input: TestStruct{Visibility: "private"}, wantErr: false},
		{name: "valid - internal", input: TestStruct{Visibility: "internal"}, wantErr: false},
		{name: "valid - empty (omitempty)", input: TestStruct{Visibility: ""}, wantErr: false},
		// Note: ParseRepoVisibility defaults to "private" for unknown, but validator checks IsValid()
		{name: "invalid - unknown", input: TestStruct{Visibility: "unknown"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidationErrors_Error(t *testing.T) {
	tests := []struct {
		name     string
		errors   ValidationErrors
		expected string
	}{
		{
			name:     "empty errors",
			errors:   ValidationErrors{},
			expected: "",
		},
		{
			name: "single error",
			errors: ValidationErrors{
				{Field: "name", Message: "is required"},
			},
			expected: "name: is required",
		},
		{
			name: "multiple errors",
			errors: ValidationErrors{
				{Field: "name", Message: "is required"},
				{Field: "email", Message: "must be a valid email address"},
			},
			expected: "name: is required; email: must be a valid email address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.errors.Error()
			if result != tt.expected {
				t.Errorf("Error() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestValidate_ArrayValidation(t *testing.T) {
	v := New()

	type TestStruct struct {
		Severities []string `validate:"max=5,dive,severity"`
	}

	tests := []struct {
		name    string
		input   TestStruct
		wantErr bool
	}{
		{
			name:    "valid - single severity",
			input:   TestStruct{Severities: []string{"critical"}},
			wantErr: false,
		},
		{
			name:    "valid - multiple severities",
			input:   TestStruct{Severities: []string{"critical", "high", "medium"}},
			wantErr: false,
		},
		{
			name:    "valid - empty array",
			input:   TestStruct{Severities: []string{}},
			wantErr: false,
		},
		{
			name:    "invalid - one invalid severity in array",
			input:   TestStruct{Severities: []string{"critical", "invalid", "high"}},
			wantErr: true,
		},
		{
			name:    "invalid - too many items",
			input:   TestStruct{Severities: []string{"critical", "high", "medium", "low", "none", "critical"}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestToSnakeCase(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{input: "Name", expected: "name"},
		{input: "FirstName", expected: "first_name"},
		{input: "HTTPStatus", expected: "h_t_t_p_status"},
		{input: "userID", expected: "user_i_d"},
		{input: "simple", expected: "simple"},
		{input: "", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := toSnakeCase(tt.input)
			if result != tt.expected {
				t.Errorf("toSnakeCase(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
