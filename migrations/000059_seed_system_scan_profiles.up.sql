-- =============================================================================
-- Migration 000059: Seed System Scan Profiles
-- OpenCTEM OSS Edition
-- =============================================================================
-- Creates 7 platform-provided scan profiles available to all tenants.
-- System profiles (is_system=true) cannot be edited/deleted by tenants,
-- but can be used directly or cloned for customization.
-- Requires system tenant from migration 000058.
-- Source: old migration 000099
-- =============================================================================

-- 1. Quick Discovery - Fast reconnaissance
INSERT INTO scan_profiles (
    id, tenant_id, name, description,
    is_default, is_system, tools_config,
    intensity, max_concurrent_scans, timeout_seconds,
    tags, metadata, quality_gate
) VALUES (
    '00000000-0000-0000-0001-000000000001',
    '00000000-0000-0000-0000-000000000000',
    'Quick Discovery',
    'Fast reconnaissance to discover subdomains and active hosts. Ideal for initial asset mapping.',
    false, true,
    '{"subfinder": {"enabled": true, "severity": "info", "timeout": 300, "template_mode": "default"}, "httpx": {"enabled": true, "severity": "info", "timeout": 300, "template_mode": "default"}}'::jsonb,
    'low', 5, 1800,
    ARRAY['recon', 'discovery', 'quick'],
    '{"use_case": "initial_mapping", "typical_duration": "5-15 minutes"}'::jsonb,
    '{"enabled": false}'::jsonb
) ON CONFLICT (tenant_id, name) DO UPDATE SET
    description = EXCLUDED.description, tools_config = EXCLUDED.tools_config,
    intensity = EXCLUDED.intensity, tags = EXCLUDED.tags,
    metadata = EXCLUDED.metadata, quality_gate = EXCLUDED.quality_gate, updated_at = NOW();

-- 2. Full SAST - Comprehensive code analysis
INSERT INTO scan_profiles (
    id, tenant_id, name, description,
    is_default, is_system, tools_config,
    intensity, max_concurrent_scans, timeout_seconds,
    tags, metadata, quality_gate
) VALUES (
    '00000000-0000-0000-0001-000000000002',
    '00000000-0000-0000-0000-000000000000',
    'Full SAST',
    'Comprehensive static application security testing. Analyzes source code for vulnerabilities.',
    false, true,
    '{"semgrep": {"enabled": true, "severity": "medium", "timeout": 600, "template_mode": "default"}}'::jsonb,
    'high', 3, 3600,
    ARRAY['sast', 'code-analysis', 'security'],
    '{"use_case": "code_review", "typical_duration": "15-45 minutes"}'::jsonb,
    '{"enabled": true, "fail_on_critical": true, "fail_on_high": false, "max_critical": 0, "max_high": 5, "max_medium": -1, "max_total": -1}'::jsonb
) ON CONFLICT (tenant_id, name) DO UPDATE SET
    description = EXCLUDED.description, tools_config = EXCLUDED.tools_config,
    intensity = EXCLUDED.intensity, tags = EXCLUDED.tags,
    metadata = EXCLUDED.metadata, quality_gate = EXCLUDED.quality_gate, updated_at = NOW();

-- 3. Secret Detection - Find leaked secrets
INSERT INTO scan_profiles (
    id, tenant_id, name, description,
    is_default, is_system, tools_config,
    intensity, max_concurrent_scans, timeout_seconds,
    tags, metadata, quality_gate
) VALUES (
    '00000000-0000-0000-0001-000000000003',
    '00000000-0000-0000-0000-000000000000',
    'Secret Detection',
    'Detect hardcoded secrets, API keys, passwords, and tokens in code repositories.',
    false, true,
    '{"gitleaks": {"enabled": true, "severity": "high", "timeout": 300, "template_mode": "default"}, "trufflehog": {"enabled": true, "severity": "high", "timeout": 300, "template_mode": "default"}}'::jsonb,
    'medium', 5, 1800,
    ARRAY['secrets', 'credentials', 'security'],
    '{"use_case": "secret_scanning", "typical_duration": "5-20 minutes"}'::jsonb,
    '{"enabled": true, "fail_on_critical": true, "fail_on_high": false, "max_critical": 0, "max_high": -1, "max_medium": -1, "max_total": -1}'::jsonb
) ON CONFLICT (tenant_id, name) DO UPDATE SET
    description = EXCLUDED.description, tools_config = EXCLUDED.tools_config,
    intensity = EXCLUDED.intensity, tags = EXCLUDED.tags,
    metadata = EXCLUDED.metadata, quality_gate = EXCLUDED.quality_gate, updated_at = NOW();

-- 4. Container Security - Image vulnerability scanning
INSERT INTO scan_profiles (
    id, tenant_id, name, description,
    is_default, is_system, tools_config,
    intensity, max_concurrent_scans, timeout_seconds,
    tags, metadata, quality_gate
) VALUES (
    '00000000-0000-0000-0001-000000000004',
    '00000000-0000-0000-0000-000000000000',
    'Container Security',
    'Scan container images for vulnerabilities, misconfigurations, and compliance issues.',
    false, true,
    '{"trivy": {"enabled": true, "severity": "medium", "timeout": 600, "template_mode": "default"}}'::jsonb,
    'medium', 3, 2400,
    ARRAY['container', 'docker', 'vulnerability', 'security'],
    '{"use_case": "container_scanning", "typical_duration": "10-30 minutes"}'::jsonb,
    '{"enabled": true, "fail_on_critical": true, "fail_on_high": false, "max_critical": 0, "max_high": -1, "max_medium": -1, "max_total": -1}'::jsonb
) ON CONFLICT (tenant_id, name) DO UPDATE SET
    description = EXCLUDED.description, tools_config = EXCLUDED.tools_config,
    intensity = EXCLUDED.intensity, tags = EXCLUDED.tags,
    metadata = EXCLUDED.metadata, quality_gate = EXCLUDED.quality_gate, updated_at = NOW();

-- 5. Web Vulnerability - DAST scanning
INSERT INTO scan_profiles (
    id, tenant_id, name, description,
    is_default, is_system, tools_config,
    intensity, max_concurrent_scans, timeout_seconds,
    tags, metadata, quality_gate
) VALUES (
    '00000000-0000-0000-0001-000000000005',
    '00000000-0000-0000-0000-000000000000',
    'Web Vulnerability',
    'Dynamic application security testing for web applications. Identifies vulnerabilities in running applications.',
    false, true,
    '{"nuclei": {"enabled": true, "severity": "medium", "timeout": 1800, "template_mode": "default"}}'::jsonb,
    'medium', 2, 7200,
    ARRAY['dast', 'web', 'vulnerability', 'security'],
    '{"use_case": "web_scanning", "typical_duration": "30-120 minutes"}'::jsonb,
    '{"enabled": true, "fail_on_critical": true, "fail_on_high": false, "max_critical": 0, "max_high": 10, "max_medium": -1, "max_total": -1}'::jsonb
) ON CONFLICT (tenant_id, name) DO UPDATE SET
    description = EXCLUDED.description, tools_config = EXCLUDED.tools_config,
    intensity = EXCLUDED.intensity, tags = EXCLUDED.tags,
    metadata = EXCLUDED.metadata, quality_gate = EXCLUDED.quality_gate, updated_at = NOW();

-- 6. CI/CD Strict - Strict quality gates for pipelines
INSERT INTO scan_profiles (
    id, tenant_id, name, description,
    is_default, is_system, tools_config,
    intensity, max_concurrent_scans, timeout_seconds,
    tags, metadata, quality_gate
) VALUES (
    '00000000-0000-0000-0001-000000000006',
    '00000000-0000-0000-0000-000000000000',
    'CI/CD Strict',
    'Strict security scanning for CI/CD pipelines. Combines SAST, secrets, and container scanning with strict quality gates.',
    false, true,
    '{"semgrep": {"enabled": true, "severity": "high", "timeout": 300, "template_mode": "default"}, "gitleaks": {"enabled": true, "severity": "high", "timeout": 180, "template_mode": "default"}, "trivy": {"enabled": true, "severity": "high", "timeout": 300, "template_mode": "default"}}'::jsonb,
    'high', 3, 1800,
    ARRAY['ci-cd', 'pipeline', 'strict', 'security'],
    '{"use_case": "ci_cd_integration", "typical_duration": "10-30 minutes"}'::jsonb,
    '{"enabled": true, "fail_on_critical": true, "fail_on_high": true, "max_critical": 0, "max_high": 0, "max_medium": 5, "max_total": -1}'::jsonb
) ON CONFLICT (tenant_id, name) DO UPDATE SET
    description = EXCLUDED.description, tools_config = EXCLUDED.tools_config,
    intensity = EXCLUDED.intensity, tags = EXCLUDED.tags,
    metadata = EXCLUDED.metadata, quality_gate = EXCLUDED.quality_gate, updated_at = NOW();

-- 7. Compliance Scan - Zero tolerance
INSERT INTO scan_profiles (
    id, tenant_id, name, description,
    is_default, is_system, tools_config,
    intensity, max_concurrent_scans, timeout_seconds,
    tags, metadata, quality_gate
) VALUES (
    '00000000-0000-0000-0001-000000000007',
    '00000000-0000-0000-0000-000000000000',
    'Compliance Scan',
    'Comprehensive security scan for compliance requirements. Uses all available tools with zero-tolerance quality gates.',
    false, true,
    '{"semgrep": {"enabled": true, "severity": "info", "timeout": 600, "template_mode": "default"}, "gitleaks": {"enabled": true, "severity": "info", "timeout": 300, "template_mode": "default"}, "trufflehog": {"enabled": true, "severity": "info", "timeout": 300, "template_mode": "default"}, "trivy": {"enabled": true, "severity": "info", "timeout": 600, "template_mode": "default"}, "nuclei": {"enabled": true, "severity": "info", "timeout": 1800, "template_mode": "default"}}'::jsonb,
    'high', 2, 14400,
    ARRAY['compliance', 'audit', 'security', 'comprehensive'],
    '{"use_case": "compliance_audit", "typical_duration": "60-240 minutes"}'::jsonb,
    '{"enabled": true, "fail_on_critical": true, "fail_on_high": true, "max_critical": 0, "max_high": 0, "max_medium": 0, "max_total": 0}'::jsonb
) ON CONFLICT (tenant_id, name) DO UPDATE SET
    description = EXCLUDED.description, tools_config = EXCLUDED.tools_config,
    intensity = EXCLUDED.intensity, tags = EXCLUDED.tags,
    metadata = EXCLUDED.metadata, quality_gate = EXCLUDED.quality_gate, updated_at = NOW();
