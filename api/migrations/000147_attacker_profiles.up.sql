-- Migration 000147: Attacker Profiles (RFC-005 Gap 9)
--
-- Reusable threat model profiles representing assumed attacker types for CTEM cycles.

CREATE TABLE IF NOT EXISTS attacker_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    profile_type VARCHAR(30) NOT NULL
      CHECK (profile_type IN (
        'external_unauth','external_stolen_creds',
        'malicious_insider','supplier_compromise','custom'
      )),
    description TEXT,
    capabilities JSONB DEFAULT '{}'::jsonb,
    assumptions TEXT,
    is_default BOOLEAN DEFAULT false,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_attacker_profiles_tenant
  ON attacker_profiles(tenant_id);

-- Seed 4 default profiles for each existing tenant
INSERT INTO attacker_profiles (tenant_id, name, profile_type, description, capabilities, assumptions, is_default)
SELECT t.id,
    'External Unauthenticated',
    'external_unauth',
    'External attacker with no credentials, using commodity tools and publicly available exploits.',
    '{"network_access":"external","credential_level":"none","persistence":false,"tools":["commodity","osint"]}'::jsonb,
    'Attacker has internet access only. No insider knowledge. Uses automated scanning and public exploits.',
    true
FROM tenants t
WHERE NOT EXISTS (SELECT 1 FROM attacker_profiles WHERE tenant_id = t.id)
UNION ALL
SELECT t.id,
    'External with Stolen Credentials',
    'external_stolen_creds',
    'External attacker who has obtained valid user credentials via phishing, credential stuffing, or breach data.',
    '{"network_access":"external","credential_level":"user","persistence":false,"tools":["commodity","credential_tools"]}'::jsonb,
    'Attacker has valid user-level credentials. Can authenticate to exposed services. May attempt privilege escalation.',
    true
FROM tenants t
WHERE NOT EXISTS (SELECT 1 FROM attacker_profiles WHERE tenant_id = t.id)
UNION ALL
SELECT t.id,
    'Malicious Insider',
    'malicious_insider',
    'Insider with legitimate access who acts maliciously. Has knowledge of internal systems and processes.',
    '{"network_access":"internal","credential_level":"user","persistence":true,"tools":["commodity","internal_knowledge"]}'::jsonb,
    'Attacker has internal network access and valid credentials. Knows organizational structure and systems. May exfiltrate data or sabotage.',
    true
FROM tenants t
WHERE NOT EXISTS (SELECT 1 FROM attacker_profiles WHERE tenant_id = t.id)
UNION ALL
SELECT t.id,
    'Supply Chain Compromise',
    'supplier_compromise',
    'Attack through a compromised third-party vendor, SaaS provider, or software dependency.',
    '{"network_access":"external","credential_level":"admin","persistence":true,"tools":["custom","supply_chain"]}'::jsonb,
    'Attacker controls a trusted vendor/dependency. May have admin-level access via federated identity or API integration. Difficult to detect.',
    true
FROM tenants t
WHERE NOT EXISTS (SELECT 1 FROM attacker_profiles WHERE tenant_id = t.id);
