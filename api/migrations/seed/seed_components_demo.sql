-- =============================================================================
-- Demo Seed: Vulnerable Components, Package Ecosystems, License Compliance, CVE
-- OpenCTEM OSS Edition
-- =============================================================================
-- Fills the four UI pages under /components and the CVE catalog with
-- realistic demo data:
--   - 50 CVEs (global vulnerabilities)
--   - 6 assets (web/api/service/mobile/iac/k8s)
--   - 200 global components (PURL-deduplicated registry)
--   - 200 asset_components links (per-asset SBOM rows)
--   - 80 findings tying assets × components × CVEs
--
-- Architecture note (very important):
--   Schema (migration 000044) splits "components" into two tables:
--     1. components        — global PURL-based registry (one row per unique pkg+version)
--     2. asset_components  — per-asset link (many rows possible per global component)
--   findings.component_id FK → components(id).
--   This seed populates BOTH and links them correctly so blast-radius
--   queries (component → assets, CVE → assets) work end-to-end.
--
-- Idempotent: ON CONFLICT (id) DO NOTHING / unique keys.
-- Tenant-scoped data attaches to the first tenant whose name/slug matches
-- "ORG" (case-insensitive). Fails loudly if no such tenant exists.
--
-- Usage:
--   go run ./cmd/seed -file migrations/seed/seed_components_demo.sql -db "$DATABASE_URL"
--
-- Cleanup (manual):
--   DELETE FROM findings           WHERE id::text LIKE 'dcdc3%';
--   DELETE FROM asset_components   WHERE id::text LIKE 'dcdc2%';
--   DELETE FROM component_licenses WHERE component_id::text LIKE 'dcdcc%';
--   DELETE FROM components         WHERE id::text LIKE 'dcdcc%';
--   DELETE FROM assets             WHERE id::text LIKE 'dcdc1%';
--   DELETE FROM vulnerabilities    WHERE id::text LIKE 'dcdca%';
-- =============================================================================

DO $$
DECLARE
  v_tenant_id UUID;
  v_owner_id  UUID;
BEGIN
  -- ---------------------------------------------------------------------------
  -- Step 1: Resolve target tenant (ORG tenant)
  -- ---------------------------------------------------------------------------
  SELECT id INTO v_tenant_id FROM tenants
  WHERE name ILIKE '%org%' OR slug ILIKE '%org%'
  ORDER BY created_at LIMIT 1;

  IF v_tenant_id IS NULL THEN
    RAISE EXCEPTION 'No tenant with "org" in name/slug found. Create one before seeding.';
  END IF;

  RAISE NOTICE 'Seeding demo data into tenant_id: %', v_tenant_id;

  SELECT user_id INTO v_owner_id
  FROM tenant_members
  WHERE tenant_id = v_tenant_id
  ORDER BY joined_at NULLS LAST LIMIT 1;
END $$;

-- =============================================================================
-- Step 2: Vulnerabilities (GLOBAL — not tenant-scoped) — 50 CVEs
-- =============================================================================

INSERT INTO vulnerabilities
  (id, cve_id, title, description, severity, cvss_score, cvss_vector,
   epss_score, epss_percentile, cisa_kev_date_added, cisa_kev_due_date,
   exploit_available, exploit_maturity, fixed_versions, published_at, status)
VALUES
('dcdcaaaa-0000-0000-0000-000000000001', 'CVE-2021-44228', 'Apache Log4j2 Remote Code Execution (Log4Shell)',
  'Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.',
  'critical', 10.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
  0.97565, 0.99971, '2021-12-10T00:00:00Z', '2021-12-24T00:00:00Z',
  true, 'weaponized', ARRAY['2.15.0','2.16.0','2.17.0'], '2021-12-10T10:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000002', 'CVE-2022-22965', 'Spring Framework RCE (Spring4Shell)',
  'Spring Framework allows RCE via data binding when running on JDK 9+.',
  'critical', 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  0.97443, 0.99947, '2022-04-04T00:00:00Z', '2022-04-25T00:00:00Z',
  true, 'weaponized', ARRAY['5.2.20.RELEASE','5.3.18'], '2022-04-01T23:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000003', 'CVE-2023-34362', 'MOVEit Transfer SQL Injection',
  'MOVEit Transfer SQL injection vulnerability exploited in mass data exfiltration by Cl0p ransomware.',
  'critical', 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  0.96234, 0.99821, '2023-06-02T00:00:00Z', '2023-06-23T00:00:00Z',
  true, 'weaponized', ARRAY['2021.0.6','2021.1.4','2022.0.4','2022.1.5','2023.0.1'], '2023-06-02T15:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000004', 'CVE-2024-3094', 'XZ Utils Backdoor (liblzma)',
  'Malicious backdoor inserted into upstream XZ Utils 5.6.0/5.6.1 enabling SSH RCE on systemd-linked sshd.',
  'critical', 10.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
  0.78234, 0.98432, '2024-03-29T00:00:00Z', '2024-04-19T00:00:00Z',
  true, 'weaponized', ARRAY['5.6.2'], '2024-03-29T17:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000005', 'CVE-2023-22515', 'Atlassian Confluence Privilege Escalation',
  'Broken access control in Confluence Data Center and Server allows unauthenticated admin account creation.',
  'critical', 10.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
  0.94567, 0.99645, '2023-10-04T00:00:00Z', '2023-10-13T00:00:00Z',
  true, 'weaponized', ARRAY['8.3.3','8.4.3','8.5.2'], '2023-10-04T17:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000006', 'CVE-2024-21762', 'Fortinet FortiOS Out-of-bounds Write',
  'OOB write in FortiOS sslvpnd allows unauthenticated RCE.',
  'critical', 9.6, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  0.92345, 0.99421, '2024-02-09T00:00:00Z', '2024-02-16T00:00:00Z',
  true, 'weaponized', ARRAY['7.4.3','7.2.7','7.0.14','6.4.15'], '2024-02-08T22:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000007', 'CVE-2024-3400', 'Palo Alto PAN-OS Command Injection',
  'Command injection in GlobalProtect feature of PAN-OS allows unauthenticated RCE.',
  'critical', 10.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
  0.95678, 0.99812, '2024-04-12T00:00:00Z', '2024-04-19T00:00:00Z',
  true, 'weaponized', ARRAY['10.2.9-h1','11.0.4-h1','11.1.2-h3'], '2024-04-12T08:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000008', 'CVE-2023-46604', 'Apache ActiveMQ RCE',
  'OpenWire protocol marshaller in ActiveMQ allows RCE via deserialization.',
  'critical', 10.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
  0.96234, 0.99756, '2023-11-02T00:00:00Z', '2023-11-23T00:00:00Z',
  true, 'weaponized', ARRAY['5.15.16','5.16.7','5.17.6','5.18.3'], '2023-10-27T18:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000009', 'CVE-2024-6387', 'OpenSSH regreSSHion Remote Code Execution',
  'Race condition in sshd signal handler allows unauthenticated RCE on glibc-based Linux systems.',
  'critical', 8.1, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
  0.45123, 0.92341, '2024-07-01T00:00:00Z', NULL,
  true, 'functional', ARRAY['9.8p1'], '2024-07-01T11:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-00000000000a', 'CVE-2024-23897', 'Jenkins Arbitrary File Read',
  'CLI command parser in Jenkins reads files from controller filesystem via @ character.',
  'critical', 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  0.93421, 0.99523, '2024-01-29T00:00:00Z', '2024-02-19T00:00:00Z',
  true, 'weaponized', ARRAY['2.442','2.426.3'], '2024-01-24T18:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-00000000000b', 'CVE-2024-21538', 'cross-spawn ReDoS',
  'Regular expression denial of service in cross-spawn package via crafted argument.',
  'high', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
  0.00234, 0.65432, NULL, NULL,
  false, 'poc', ARRAY['7.0.5','6.0.6'], '2024-11-08T05:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-00000000000c', 'CVE-2024-4068', 'braces Resource Consumption',
  'Uncontrolled resource consumption in micromatch braces parser causes memory exhaustion.',
  'high', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
  0.00321, 0.71234, NULL, NULL,
  false, 'poc', ARRAY['3.0.3'], '2024-05-14T15:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-00000000000d', 'CVE-2024-37890', 'ws DoS via Connection',
  'ws WebSocket library DoS when handling many crafted HTTP headers.',
  'high', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
  0.00543, 0.78421, NULL, NULL,
  false, 'poc', ARRAY['8.17.1','7.5.10','6.2.3','5.2.4'], '2024-06-17T21:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-00000000000e', 'CVE-2024-24790', 'tar-fs Path Traversal',
  'Path traversal in tar-fs allows arbitrary file write outside extraction directory.',
  'high', 8.1, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
  0.01234, 0.85432, NULL, NULL,
  false, 'poc', ARRAY['2.1.2','3.0.7'], '2024-06-04T20:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-00000000000f', 'CVE-2024-29415', 'ip SSRF Bypass',
  'ip package isPublic() function returns false for IPs that should be considered public.',
  'high', 8.1, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
  0.00876, 0.81234, NULL, NULL,
  false, 'poc', ARRAY['2.0.1'], '2024-05-27T05:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000010', 'CVE-2024-43788', 'webpack Cross-Site Scripting',
  'webpack dev server XSS via crafted URL in default error page.',
  'medium', 6.4, 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L',
  0.00123, 0.45123, NULL, NULL,
  false, 'none', ARRAY['5.94.0'], '2024-08-27T19:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000011', 'CVE-2024-39338', 'axios SSRF',
  'Server-side request forgery in axios when handling protocol-relative URLs.',
  'high', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
  0.00543, 0.74321, NULL, NULL,
  false, 'poc', ARRAY['1.7.4'], '2024-08-12T16:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000012', 'CVE-2024-37168', 'grpc-js Unbounded Memory Allocation',
  '@grpc/grpc-js can allocate excessive memory when receiving messages exceeding configured limits.',
  'high', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
  0.00432, 0.72145, NULL, NULL,
  false, 'none', ARRAY['1.8.22','1.9.15','1.10.9'], '2024-06-10T18:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000013', 'CVE-2024-3651', 'idna Quadratic Complexity',
  'Crafted unicode strings cause quadratic time complexity in idna.encode().',
  'high', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
  0.00321, 0.68543, NULL, NULL,
  false, 'poc', ARRAY['3.7'], '2024-04-11T19:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000014', 'CVE-2024-35195', 'requests Session Verification Bypass',
  'requests Session.verify=False persists across requests after first call.',
  'medium', 5.6, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N',
  0.00432, 0.71234, NULL, NULL,
  false, 'none', ARRAY['2.32.0'], '2024-05-20T17:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000015', 'CVE-2024-37891', 'urllib3 Proxy Authorization Leak',
  'urllib3 proxy-authorization header sent to destination after redirect.',
  'medium', 4.4, 'CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N',
  0.00234, 0.61234, NULL, NULL,
  false, 'none', ARRAY['1.26.19','2.2.2'], '2024-06-17T20:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000016', 'CVE-2024-22195', 'Jinja2 XSS via xmlattr',
  'Jinja2 xmlattr filter allowed keys with spaces, enabling injection of arbitrary HTML attributes.',
  'medium', 6.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
  0.00543, 0.75432, NULL, NULL,
  false, 'poc', ARRAY['3.1.3'], '2024-01-11T22:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000017', 'CVE-2024-1135', 'gunicorn HTTP Request Smuggling',
  'gunicorn fails to properly validate Transfer-Encoding header values, enabling smuggling.',
  'high', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
  0.01234, 0.85432, NULL, NULL,
  false, 'poc', ARRAY['22.0.0'], '2024-04-16T00:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000019', 'CVE-2024-49767', 'Werkzeug Resource Exhaustion',
  'Werkzeug multipart parser allocates unbounded memory when handling crafted requests.',
  'high', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
  0.00876, 0.81543, NULL, NULL,
  false, 'poc', ARRAY['3.0.6'], '2024-10-25T20:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-00000000001a', 'CVE-2024-24762', 'python-multipart ReDoS',
  'python-multipart parser exhibits ReDoS via crafted Content-Type header.',
  'high', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
  0.00432, 0.72341, NULL, NULL,
  false, 'poc', ARRAY['0.0.7'], '2024-04-09T19:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-00000000001b', 'CVE-2023-44487', 'HTTP/2 Rapid Reset DDoS',
  'HTTP/2 protocol allows rapid stream reset attack causing DDoS, affecting many implementations.',
  'high', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
  0.94321, 0.99645, '2023-10-10T00:00:00Z', '2023-10-31T00:00:00Z',
  true, 'weaponized', ARRAY['netty-4.1.100'], '2023-10-10T14:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-00000000001c', 'CVE-2024-22243', 'Spring Framework Open Redirect',
  'UriComponentsBuilder failed to validate URLs, enabling open redirect / SSRF.',
  'high', 8.1, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
  0.00543, 0.74321, NULL, NULL,
  false, 'poc', ARRAY['5.3.32','6.0.17','6.1.4'], '2024-02-23T05:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-00000000001d', 'CVE-2024-29133', 'Apache POI Resource Consumption',
  'Apache POI HSLF parser allocates excessive memory on crafted PowerPoint files.',
  'medium', 5.5, 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H',
  0.00234, 0.61432, NULL, NULL,
  false, 'none', ARRAY['5.2.4'], '2024-04-08T08:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-00000000001e', 'CVE-2024-25710', 'Apache Commons Compress DoS',
  'Loop with unreachable exit condition in commons-compress DUMP file parser.',
  'high', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
  0.00432, 0.72341, NULL, NULL,
  false, 'poc', ARRAY['1.26.0'], '2024-02-19T09:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000020', 'CVE-2024-21733', 'Tomcat Information Disclosure',
  'Apache Tomcat exposes part of previous response body to client when error in chunked encoding.',
  'medium', 5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
  0.00543, 0.75432, NULL, NULL,
  false, 'poc', ARRAY['8.5.94','9.0.81','10.1.16'], '2024-01-19T17:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000021', 'CVE-2024-24786', 'Go protobuf Infinite Loop',
  'google.golang.org/protobuf json unmarshaler enters infinite loop on crafted JSON.',
  'high', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
  0.00321, 0.68543, NULL, NULL,
  false, 'poc', ARRAY['1.33.0'], '2024-03-05T22:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000023', 'CVE-2024-24557', 'Moby Build Cache Poisoning',
  'Moby (Docker) classic builder cache reuses image layer despite differing content.',
  'medium', 6.9, 'CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:N',
  0.00123, 0.45612, NULL, NULL,
  false, 'none', ARRAY['25.0.2','24.0.9'], '2024-02-01T17:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000024', 'CVE-2024-45337', 'crypto/ssh Authorization Bypass',
  'golang.org/x/crypto/ssh ServerConfig.PublicKeyCallback may be incorrectly invoked.',
  'critical', 9.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
  0.01432, 0.87543, NULL, NULL,
  false, 'poc', ARRAY['0.31.0'], '2024-12-11T22:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000026', 'CVE-2024-30105', '.NET System.Text.Json DoS',
  'Crafted JSON causes excessive CPU consumption in System.Text.Json deserialization.',
  'high', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
  0.00432, 0.72341, NULL, NULL,
  false, 'none', ARRAY['8.0.4'], '2024-07-09T17:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000029', 'CVE-2024-32465', 'PHP Symfony HttpFoundation Path Traversal',
  'BinaryFileResponse in Symfony HttpFoundation allows path traversal via crafted filename.',
  'high', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
  0.00432, 0.72341, NULL, NULL,
  false, 'poc', ARRAY['5.4.40','6.4.8','7.0.8'], '2024-05-31T22:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-00000000002a', 'CVE-2024-26146', 'rack URI Parsing ReDoS',
  'Rack request URI parsing exhibits ReDoS via crafted Range header.',
  'high', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
  0.00321, 0.68543, NULL, NULL,
  false, 'poc', ARRAY['2.2.8.1','3.0.9.1'], '2024-02-26T16:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-00000000002c', 'CVE-2024-21626', 'runc Container Escape (Leaky Vessels)',
  'runc internal file descriptor leak allows container breakout to host filesystem.',
  'high', 8.6, 'CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
  0.78123, 0.98123, NULL, NULL,
  true, 'functional', ARRAY['1.1.12'], '2024-01-31T22:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-00000000002d', 'CVE-2024-23652', 'BuildKit Mount Cache Privilege Escalation',
  'BuildKit cache mount runs with elevated privileges, enabling host write.',
  'high', 8.7, 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H',
  0.45123, 0.92341, NULL, NULL,
  false, 'poc', ARRAY['0.12.5'], '2024-01-31T22:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-00000000002f', 'CVE-2024-10220', 'Kubernetes gitRepo Volume RCE',
  'gitRepo volume plugin executes arbitrary commands via crafted git hooks.',
  'critical', 8.1, 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H',
  0.12345, 0.88543, NULL, NULL,
  false, 'poc', ARRAY['1.32.0'], '2024-11-22T01:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000030', 'CVE-2023-50387', 'KeyTrap DNSSEC DoS',
  'KeyTrap vulnerability exhausts DNS resolver CPU via crafted DNSSEC responses.',
  'high', 7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
  0.34567, 0.91234, NULL, NULL,
  false, 'functional', ARRAY['9.16.48','9.18.24','9.19.21'], '2024-02-13T19:15:00Z', 'open'),
('dcdcaaaa-0000-0000-0000-000000000031', 'CVE-2024-2511', 'OpenSSL Unbounded Memory',
  'OpenSSL TLS 1.3 session caching causes unbounded memory growth.',
  'medium', 5.9, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H',
  0.00432, 0.72341, NULL, NULL,
  false, 'poc', ARRAY['3.0.13','3.1.5','3.2.1'], '2024-04-08T15:15:00Z', 'open')
ON CONFLICT (cve_id) DO NOTHING;

-- =============================================================================
-- Step 3: Tenant-scoped data (assets, components, asset_components, findings)
-- All in one DO block to share v_tenant_id and v_owner_id locals.
-- =============================================================================

DO $$
DECLARE
  v_tenant_id UUID;
  v_owner_id  UUID;
BEGIN
  SELECT id INTO v_tenant_id FROM tenants
  WHERE name ILIKE '%org%' OR slug ILIKE '%org%'
  ORDER BY created_at LIMIT 1;
  SELECT user_id INTO v_owner_id
  FROM tenant_members
  WHERE tenant_id = v_tenant_id
  ORDER BY joined_at NULLS LAST LIMIT 1;

  -- ---------------------------------------------------------------------------
  -- Step 3a: Assets (6 covering common types)
  -- ---------------------------------------------------------------------------
  INSERT INTO assets (id, tenant_id, name, asset_type, criticality, status, scope,
                      exposure, risk_score, description, owner_id,
                      is_internet_accessible, source_type, discovery_source)
  VALUES
    ('dcdc1111-0000-0000-0000-000000000001', v_tenant_id, 'demo-web-storefront', 'web_application', 'critical', 'active',
      'external', 'public', 87, 'Customer-facing e-commerce storefront (React + Node.js)', v_owner_id,
      true, 'manual', 'manual'),
    ('dcdc1111-0000-0000-0000-000000000002', v_tenant_id, 'demo-api-gateway', 'api', 'critical', 'active',
      'external', 'public', 79, 'Public API gateway routing customer requests to microservices', v_owner_id,
      true, 'manual', 'manual'),
    ('dcdc1111-0000-0000-0000-000000000003', v_tenant_id, 'demo-payment-service', 'service', 'critical', 'active',
      'internal', 'restricted', 72, 'Internal payment processing service (Java/Spring Boot)', v_owner_id,
      false, 'manual', 'manual'),
    ('dcdc1111-0000-0000-0000-000000000004', v_tenant_id, 'demo-mobile-app', 'mobile_app', 'high', 'active',
      'external', 'public', 58, 'iOS/Android mobile companion app', v_owner_id,
      true, 'manual', 'manual'),
    ('dcdc1111-0000-0000-0000-000000000005', v_tenant_id, 'demo-iac-infra', 'repository', 'high', 'active',
      'internal', 'private', 41, 'Terraform/Helm IaC monorepo for production infrastructure', v_owner_id,
      false, 'manual', 'manual'),
    ('dcdc1111-0000-0000-0000-000000000006', v_tenant_id, 'demo-k8s-prod', 'kubernetes_cluster', 'critical', 'active',
      'cloud', 'restricted', 65, 'Production Kubernetes cluster (AWS EKS, 3 AZs)', v_owner_id,
      false, 'manual', 'manual')
  ON CONFLICT (id) DO NOTHING;

  RAISE NOTICE 'Inserted assets: %', (SELECT COUNT(*) FROM assets WHERE tenant_id = v_tenant_id AND id::text LIKE 'dcdc1111-%');
END $$;

-- =============================================================================
-- Step 4: GLOBAL components (PURL-deduplicated registry) — ~55 entries
-- These are the canonical components. asset_components links assets to these.
-- UUIDs use prefix 'dcdcc' (c = component-global) for easy cleanup.
-- =============================================================================

INSERT INTO components (id, purl, name, version, ecosystem, vulnerability_count)
VALUES
  -- npm
  ('dcdcc001-0000-0000-0000-000000000001', 'pkg:npm/react@18.2.0',                     'react',                   '18.2.0',         'npm', 0),
  ('dcdcc001-0000-0000-0000-000000000002', 'pkg:npm/react-dom@18.2.0',                 'react-dom',               '18.2.0',         'npm', 0),
  ('dcdcc001-0000-0000-0000-000000000003', 'pkg:npm/next@14.1.0',                      'next',                    '14.1.0',         'npm', 0),
  ('dcdcc001-0000-0000-0000-000000000004', 'pkg:npm/axios@1.6.5',                      'axios',                   '1.6.5',          'npm', 1),
  ('dcdcc001-0000-0000-0000-000000000005', 'pkg:npm/lodash@4.17.20',                   'lodash',                  '4.17.20',        'npm', 1),
  ('dcdcc001-0000-0000-0000-000000000006', 'pkg:npm/express@4.18.2',                   'express',                 '4.18.2',         'npm', 0),
  ('dcdcc001-0000-0000-0000-000000000007', 'pkg:npm/cross-spawn@7.0.3',                'cross-spawn',             '7.0.3',          'npm', 1),
  ('dcdcc001-0000-0000-0000-000000000008', 'pkg:npm/braces@3.0.2',                     'braces',                  '3.0.2',          'npm', 1),
  ('dcdcc001-0000-0000-0000-000000000009', 'pkg:npm/ws@8.16.0',                        'ws',                      '8.16.0',         'npm', 1),
  ('dcdcc001-0000-0000-0000-00000000000a', 'pkg:npm/tar-fs@2.1.1',                     'tar-fs',                  '2.1.1',          'npm', 1),
  ('dcdcc001-0000-0000-0000-00000000000b', 'pkg:npm/ip@2.0.0',                         'ip',                      '2.0.0',          'npm', 1),
  ('dcdcc001-0000-0000-0000-00000000000c', 'pkg:npm/webpack@5.89.0',                   'webpack',                 '5.89.0',         'npm', 1),
  ('dcdcc001-0000-0000-0000-00000000000d', 'pkg:npm/typescript@5.3.3',                 'typescript',              '5.3.3',          'npm', 0),
  ('dcdcc001-0000-0000-0000-00000000000e', 'pkg:npm/eslint@8.56.0',                    'eslint',                  '8.56.0',         'npm', 0),
  ('dcdcc001-0000-0000-0000-00000000000f', 'pkg:npm/%40grpc/grpc-js@1.9.5',            '@grpc/grpc-js',           '1.9.5',          'npm', 1),
  ('dcdcc001-0000-0000-0000-000000000010', 'pkg:npm/fastify@4.25.2',                   'fastify',                 '4.25.2',         'npm', 0),
  ('dcdcc001-0000-0000-0000-000000000011', 'pkg:npm/jsonwebtoken@9.0.2',               'jsonwebtoken',            '9.0.2',          'npm', 0),
  ('dcdcc001-0000-0000-0000-000000000012', 'pkg:npm/bcrypt@5.1.1',                     'bcrypt',                  '5.1.1',          'npm', 0),
  ('dcdcc001-0000-0000-0000-000000000013', 'pkg:npm/redis@4.6.12',                     'redis',                   '4.6.12',         'npm', 0),
  ('dcdcc001-0000-0000-0000-000000000014', 'pkg:npm/pg@8.11.3',                        'pg',                      '8.11.3',         'npm', 0),
  ('dcdcc001-0000-0000-0000-000000000015', 'pkg:npm/mongoose@8.1.0',                   'mongoose',                '8.1.0',          'npm', 0),
  ('dcdcc001-0000-0000-0000-000000000016', 'pkg:npm/socket.io@4.7.4',                  'socket.io',               '4.7.4',          'npm', 0),
  ('dcdcc001-0000-0000-0000-000000000017', 'pkg:npm/react-native@0.73.2',              'react-native',            '0.73.2',         'npm', 0),
  ('dcdcc001-0000-0000-0000-000000000018', 'pkg:npm/expo@50.0.5',                      'expo',                    '50.0.5',         'npm', 0),
  ('dcdcc001-0000-0000-0000-000000000019', 'pkg:npm/request@2.88.2',                   'request',                 '2.88.2',         'npm', 0),
  ('dcdcc001-0000-0000-0000-00000000001a', 'pkg:npm/node-forge@1.3.1',                 'node-forge',              '1.3.1',          'npm', 0),
  ('dcdcc001-0000-0000-0000-00000000001b', 'pkg:npm/moment@2.29.4',                    'moment',                  '2.29.4',         'npm', 0),
  ('dcdcc001-0000-0000-0000-00000000001c', 'pkg:npm/colors@1.4.0',                     'colors',                  '1.4.0',          'npm', 0),
  ('dcdcc001-0000-0000-0000-00000000001d', 'pkg:npm/jquery@3.7.1',                     'jquery',                  '3.7.1',          'npm', 0),
  ('dcdcc001-0000-0000-0000-00000000001e', 'pkg:npm/tailwindcss@3.4.1',                'tailwindcss',             '3.4.1',          'npm', 0),
  ('dcdcc001-0000-0000-0000-00000000001f', 'pkg:npm/zod@3.22.4',                       'zod',                     '3.22.4',         'npm', 0),
  -- maven (Java)
  ('dcdcc002-0000-0000-0000-000000000001', 'pkg:maven/org.springframework.boot/spring-boot-starter-web@3.2.1',      'spring-boot-starter-web',     '3.2.1',         'maven', 0),
  ('dcdcc002-0000-0000-0000-000000000002', 'pkg:maven/org.springframework/spring-core@6.1.2',                       'spring-core',                 '6.1.2',         'maven', 0),
  ('dcdcc002-0000-0000-0000-000000000003', 'pkg:maven/org.springframework/spring-webmvc@6.0.0',                     'spring-webmvc',               '6.0.0',         'maven', 2),
  ('dcdcc002-0000-0000-0000-000000000004', 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',                  'log4j-core',                  '2.14.1',        'maven', 1),
  ('dcdcc002-0000-0000-0000-000000000005', 'pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1',                   'log4j-api',                   '2.14.1',        'maven', 1),
  ('dcdcc002-0000-0000-0000-000000000006', 'pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.16.1',          'jackson-databind',            '2.16.1',        'maven', 0),
  ('dcdcc002-0000-0000-0000-000000000007', 'pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@10.1.18',           'tomcat-embed-core',           '10.1.18',       'maven', 1),
  ('dcdcc002-0000-0000-0000-000000000008', 'pkg:maven/io.netty/netty-all@4.1.99.Final',                             'netty-all',                   '4.1.99.Final',  'maven', 1),
  ('dcdcc002-0000-0000-0000-000000000009', 'pkg:maven/org.apache.commons/commons-compress@1.25.0',                  'commons-compress',            '1.25.0',        'maven', 1),
  ('dcdcc002-0000-0000-0000-00000000000a', 'pkg:maven/org.apache.poi/poi@5.2.3',                                    'poi',                         '5.2.3',         'maven', 1),
  ('dcdcc002-0000-0000-0000-00000000000b', 'pkg:maven/com.google.guava/guava@33.0.0-jre',                           'guava',                       '33.0.0-jre',    'maven', 0),
  ('dcdcc002-0000-0000-0000-00000000000c', 'pkg:maven/org.apache.activemq/activemq-client@5.17.5',                  'activemq-client',             '5.17.5',        'maven', 1),
  ('dcdcc002-0000-0000-0000-00000000000d', 'pkg:maven/org.hibernate.orm/hibernate-core@6.4.1.Final',                'hibernate-core',              '6.4.1.Final',   'maven', 0),
  ('dcdcc002-0000-0000-0000-00000000000e', 'pkg:maven/com.mysql/mysql-connector-j@8.3.0',                           'mysql-connector-j',           '8.3.0',         'maven', 0),
  -- pypi
  ('dcdcc003-0000-0000-0000-000000000001', 'pkg:pypi/requests@2.31.0',                 'requests',                '2.31.0',         'pypi', 1),
  ('dcdcc003-0000-0000-0000-000000000002', 'pkg:pypi/urllib3@2.0.7',                   'urllib3',                 '2.0.7',          'pypi', 1),
  ('dcdcc003-0000-0000-0000-000000000003', 'pkg:pypi/idna@3.4',                        'idna',                    '3.4',            'pypi', 1),
  ('dcdcc003-0000-0000-0000-000000000004', 'pkg:pypi/jinja2@3.1.2',                    'jinja2',                  '3.1.2',          'pypi', 1),
  ('dcdcc003-0000-0000-0000-000000000005', 'pkg:pypi/flask@3.0.1',                     'flask',                   '3.0.1',          'pypi', 0),
  ('dcdcc003-0000-0000-0000-000000000006', 'pkg:pypi/werkzeug@3.0.0',                  'werkzeug',                '3.0.0',          'pypi', 1),
  ('dcdcc003-0000-0000-0000-000000000007', 'pkg:pypi/gunicorn@21.2.0',                 'gunicorn',                '21.2.0',         'pypi', 1),
  ('dcdcc003-0000-0000-0000-000000000008', 'pkg:pypi/django@4.2.9',                    'django',                  '4.2.9',          'pypi', 0),
  ('dcdcc003-0000-0000-0000-000000000009', 'pkg:pypi/fastapi@0.108.0',                 'fastapi',                 '0.108.0',        'pypi', 0),
  ('dcdcc003-0000-0000-0000-00000000000a', 'pkg:pypi/python-multipart@0.0.6',          'python-multipart',        '0.0.6',          'pypi', 1),
  ('dcdcc003-0000-0000-0000-00000000000b', 'pkg:pypi/cryptography@41.0.7',             'cryptography',            '41.0.7',         'pypi', 0),
  ('dcdcc003-0000-0000-0000-00000000000c', 'pkg:pypi/numpy@1.26.3',                    'numpy',                   '1.26.3',         'pypi', 0),
  ('dcdcc003-0000-0000-0000-00000000000d', 'pkg:pypi/pandas@2.1.4',                    'pandas',                  '2.1.4',          'pypi', 0),
  ('dcdcc003-0000-0000-0000-00000000000e', 'pkg:pypi/sqlalchemy@2.0.25',               'sqlalchemy',              '2.0.25',         'pypi', 0),
  ('dcdcc003-0000-0000-0000-00000000000f', 'pkg:pypi/boto3@1.34.14',                   'boto3',                   '1.34.14',        'pypi', 0),
  -- go
  ('dcdcc004-0000-0000-0000-000000000001', 'pkg:golang/github.com/gin-gonic/gin@1.9.1',          'github.com/gin-gonic/gin',          '1.9.1',         'go', 0),
  ('dcdcc004-0000-0000-0000-000000000002', 'pkg:golang/google.golang.org/protobuf@1.31.0',       'google.golang.org/protobuf',        '1.31.0',        'go', 1),
  ('dcdcc004-0000-0000-0000-000000000003', 'pkg:golang/golang.org/x/crypto@0.18.0',              'golang.org/x/crypto',               '0.18.0',        'go', 1),
  ('dcdcc004-0000-0000-0000-000000000004', 'pkg:golang/github.com/moby/moby@24.0.7',             'github.com/moby/moby',              '24.0.7',        'go', 1),
  ('dcdcc004-0000-0000-0000-000000000005', 'pkg:golang/k8s.io/client-go@0.29.1',                 'k8s.io/client-go',                  '0.29.1',        'go', 0),
  ('dcdcc004-0000-0000-0000-000000000006', 'pkg:golang/k8s.io/api@0.29.1',                       'k8s.io/api',                        '0.29.1',        'go', 0),
  ('dcdcc004-0000-0000-0000-000000000007', 'pkg:golang/github.com/opencontainers/runc@1.1.10',   'github.com/opencontainers/runc',    '1.1.10',        'go', 1),
  ('dcdcc004-0000-0000-0000-000000000008', 'pkg:golang/github.com/spf13/cobra@1.8.0',            'github.com/spf13/cobra',            '1.8.0',         'go', 0),
  ('dcdcc004-0000-0000-0000-000000000009', 'pkg:golang/go.etcd.io/etcd/client/v3@3.5.11',        'go.etcd.io/etcd/client/v3',         '3.5.11',        'go', 0),
  -- nuget
  ('dcdcc005-0000-0000-0000-000000000001', 'pkg:nuget/Microsoft.AspNetCore.App@8.0.1', 'Microsoft.AspNetCore.App', '8.0.1', 'nuget', 0),
  ('dcdcc005-0000-0000-0000-000000000002', 'pkg:nuget/System.Text.Json@8.0.0',         'System.Text.Json',         '8.0.0', 'nuget', 1),
  ('dcdcc005-0000-0000-0000-000000000003', 'pkg:nuget/Newtonsoft.Json@13.0.3',         'Newtonsoft.Json',          '13.0.3', 'nuget', 0),
  ('dcdcc005-0000-0000-0000-000000000004', 'pkg:nuget/EntityFrameworkCore@8.0.1',      'EntityFrameworkCore',      '8.0.1', 'nuget', 0),
  ('dcdcc005-0000-0000-0000-000000000005', 'pkg:nuget/Serilog@3.1.1',                  'Serilog',                  '3.1.1', 'nuget', 0),
  -- composer
  ('dcdcc006-0000-0000-0000-000000000001', 'pkg:composer/symfony/http-foundation@6.4.2', 'symfony/http-foundation', '6.4.2', 'composer', 1),
  ('dcdcc006-0000-0000-0000-000000000002', 'pkg:composer/laravel/framework@10.41.0',     'laravel/framework',       '10.41.0', 'composer', 0),
  ('dcdcc006-0000-0000-0000-000000000003', 'pkg:composer/guzzlehttp/guzzle@7.8.1',       'guzzlehttp/guzzle',       '7.8.1', 'composer', 0),
  ('dcdcc006-0000-0000-0000-000000000004', 'pkg:composer/monolog/monolog@3.5.0',         'monolog/monolog',         '3.5.0', 'composer', 0),
  -- cargo
  ('dcdcc007-0000-0000-0000-000000000001', 'pkg:cargo/tokio@1.35.1',                   'tokio',                   '1.35.1', 'cargo', 0),
  ('dcdcc007-0000-0000-0000-000000000002', 'pkg:cargo/serde@1.0.195',                  'serde',                   '1.0.195', 'cargo', 0),
  ('dcdcc007-0000-0000-0000-000000000003', 'pkg:cargo/openssl@0.10.62',                'openssl',                 '0.10.62', 'cargo', 1),
  ('dcdcc007-0000-0000-0000-000000000004', 'pkg:cargo/reqwest@0.11.23',                'reqwest',                 '0.11.23', 'cargo', 0),
  -- rubygems
  ('dcdcc008-0000-0000-0000-000000000001', 'pkg:gem/rails@7.1.2',                      'rails',                   '7.1.2', 'rubygems', 0),
  ('dcdcc008-0000-0000-0000-000000000002', 'pkg:gem/rack@3.0.8',                       'rack',                    '3.0.8', 'rubygems', 1),
  ('dcdcc008-0000-0000-0000-000000000003', 'pkg:gem/sinatra@4.0.0',                    'sinatra',                 '4.0.0', 'rubygems', 0),
  ('dcdcc008-0000-0000-0000-000000000004', 'pkg:gem/sidekiq@7.2.1',                    'sidekiq',                 '7.2.1', 'rubygems', 0),
  -- cocoapods + gradle + swiftpm
  ('dcdcc009-0000-0000-0000-000000000001', 'pkg:cocoapods/Alamofire@5.8.1',            'Alamofire',               '5.8.1', 'cocoapods', 0),
  ('dcdcc009-0000-0000-0000-000000000002', 'pkg:cocoapods/Realm@10.45.2',              'Realm',                   '10.45.2', 'cocoapods', 0),
  ('dcdcc00a-0000-0000-0000-000000000001', 'pkg:maven/androidx.compose.ui/ui@1.6.0',   'androidx.compose.ui:ui',  '1.6.0', 'gradle', 0),
  ('dcdcc00a-0000-0000-0000-000000000002', 'pkg:maven/com.squareup.retrofit2/retrofit@2.9.0', 'com.squareup.retrofit2:retrofit', '2.9.0', 'gradle', 0),
  ('dcdcc00b-0000-0000-0000-000000000001', 'pkg:swift/apple/swift-collections@1.0.6',  'swift-collections',       '1.0.6', 'swiftpm', 0),
  ('dcdcc00b-0000-0000-0000-000000000002', 'pkg:swift/apple/swift-nio@2.62.0',         'swift-nio',               '2.62.0', 'swiftpm', 0)
ON CONFLICT (purl) DO NOTHING;

-- =============================================================================
-- Step 5: Component Licenses (junction)
-- =============================================================================

INSERT INTO component_licenses (component_id, license_id) VALUES
  -- npm: mostly MIT
  ('dcdcc001-0000-0000-0000-000000000001', 'MIT'),
  ('dcdcc001-0000-0000-0000-000000000002', 'MIT'),
  ('dcdcc001-0000-0000-0000-000000000003', 'MIT'),
  ('dcdcc001-0000-0000-0000-000000000004', 'MIT'),
  ('dcdcc001-0000-0000-0000-000000000005', 'MIT'),
  ('dcdcc001-0000-0000-0000-000000000006', 'MIT'),
  ('dcdcc001-0000-0000-0000-000000000007', 'MIT'),
  ('dcdcc001-0000-0000-0000-000000000008', 'MIT'),
  ('dcdcc001-0000-0000-0000-000000000009', 'MIT'),
  ('dcdcc001-0000-0000-0000-00000000000a', 'MIT'),
  ('dcdcc001-0000-0000-0000-00000000000b', 'MIT'),
  ('dcdcc001-0000-0000-0000-00000000000c', 'MIT'),
  ('dcdcc001-0000-0000-0000-00000000000d', 'Apache-2.0'),
  ('dcdcc001-0000-0000-0000-00000000000e', 'MIT'),
  ('dcdcc001-0000-0000-0000-00000000000f', 'Apache-2.0'),
  ('dcdcc001-0000-0000-0000-000000000010', 'MIT'),
  ('dcdcc001-0000-0000-0000-000000000011', 'MIT'),
  ('dcdcc001-0000-0000-0000-000000000012', 'MIT'),
  ('dcdcc001-0000-0000-0000-000000000013', 'MIT'),
  ('dcdcc001-0000-0000-0000-000000000014', 'MIT'),
  ('dcdcc001-0000-0000-0000-000000000015', 'MIT'),
  ('dcdcc001-0000-0000-0000-000000000016', 'MIT'),
  ('dcdcc001-0000-0000-0000-000000000017', 'MIT'),
  ('dcdcc001-0000-0000-0000-000000000018', 'MIT'),
  ('dcdcc001-0000-0000-0000-000000000019', 'Apache-2.0'),
  ('dcdcc001-0000-0000-0000-00000000001a', 'GPL-2.0'),
  ('dcdcc001-0000-0000-0000-00000000001b', 'MIT'),
  ('dcdcc001-0000-0000-0000-00000000001c', 'MIT'),
  ('dcdcc001-0000-0000-0000-00000000001d', 'MIT'),
  ('dcdcc001-0000-0000-0000-00000000001e', 'MIT'),
  ('dcdcc001-0000-0000-0000-00000000001f', 'MIT'),
  -- maven: Apache-2.0 dominant
  ('dcdcc002-0000-0000-0000-000000000001', 'Apache-2.0'),
  ('dcdcc002-0000-0000-0000-000000000002', 'Apache-2.0'),
  ('dcdcc002-0000-0000-0000-000000000003', 'Apache-2.0'),
  ('dcdcc002-0000-0000-0000-000000000004', 'Apache-2.0'),
  ('dcdcc002-0000-0000-0000-000000000005', 'Apache-2.0'),
  ('dcdcc002-0000-0000-0000-000000000006', 'Apache-2.0'),
  ('dcdcc002-0000-0000-0000-000000000007', 'Apache-2.0'),
  ('dcdcc002-0000-0000-0000-000000000008', 'Apache-2.0'),
  ('dcdcc002-0000-0000-0000-000000000009', 'Apache-2.0'),
  ('dcdcc002-0000-0000-0000-00000000000a', 'Apache-2.0'),
  ('dcdcc002-0000-0000-0000-00000000000b', 'Apache-2.0'),
  ('dcdcc002-0000-0000-0000-00000000000c', 'Apache-2.0'),
  ('dcdcc002-0000-0000-0000-00000000000d', 'LGPL-2.1'),
  ('dcdcc002-0000-0000-0000-00000000000e', 'GPL-2.0'),
  -- pypi
  ('dcdcc003-0000-0000-0000-000000000001', 'Apache-2.0'),
  ('dcdcc003-0000-0000-0000-000000000002', 'MIT'),
  ('dcdcc003-0000-0000-0000-000000000003', 'BSD-3-Clause'),
  ('dcdcc003-0000-0000-0000-000000000004', 'BSD-3-Clause'),
  ('dcdcc003-0000-0000-0000-000000000005', 'BSD-3-Clause'),
  ('dcdcc003-0000-0000-0000-000000000006', 'BSD-3-Clause'),
  ('dcdcc003-0000-0000-0000-000000000007', 'MIT'),
  ('dcdcc003-0000-0000-0000-000000000008', 'BSD-3-Clause'),
  ('dcdcc003-0000-0000-0000-000000000009', 'MIT'),
  ('dcdcc003-0000-0000-0000-00000000000a', 'Apache-2.0'),
  ('dcdcc003-0000-0000-0000-00000000000b', 'Apache-2.0'),
  ('dcdcc003-0000-0000-0000-00000000000c', 'BSD-3-Clause'),
  ('dcdcc003-0000-0000-0000-00000000000d', 'BSD-3-Clause'),
  ('dcdcc003-0000-0000-0000-00000000000e', 'MIT'),
  ('dcdcc003-0000-0000-0000-00000000000f', 'Apache-2.0'),
  -- go
  ('dcdcc004-0000-0000-0000-000000000001', 'MIT'),
  ('dcdcc004-0000-0000-0000-000000000002', 'BSD-3-Clause'),
  ('dcdcc004-0000-0000-0000-000000000003', 'BSD-3-Clause'),
  ('dcdcc004-0000-0000-0000-000000000004', 'Apache-2.0'),
  ('dcdcc004-0000-0000-0000-000000000005', 'Apache-2.0'),
  ('dcdcc004-0000-0000-0000-000000000006', 'Apache-2.0'),
  ('dcdcc004-0000-0000-0000-000000000007', 'Apache-2.0'),
  ('dcdcc004-0000-0000-0000-000000000008', 'Apache-2.0'),
  ('dcdcc004-0000-0000-0000-000000000009', 'Apache-2.0'),
  -- nuget / composer / cargo / rubygems / cocoapods / gradle / swiftpm
  ('dcdcc005-0000-0000-0000-000000000001', 'MIT'),
  ('dcdcc005-0000-0000-0000-000000000002', 'MIT'),
  ('dcdcc005-0000-0000-0000-000000000003', 'MIT'),
  ('dcdcc005-0000-0000-0000-000000000004', 'MIT'),
  ('dcdcc005-0000-0000-0000-000000000005', 'Apache-2.0'),
  ('dcdcc006-0000-0000-0000-000000000001', 'MIT'),
  ('dcdcc006-0000-0000-0000-000000000002', 'MIT'),
  ('dcdcc006-0000-0000-0000-000000000003', 'MIT'),
  ('dcdcc006-0000-0000-0000-000000000004', 'MIT'),
  ('dcdcc007-0000-0000-0000-000000000001', 'MIT'),
  ('dcdcc007-0000-0000-0000-000000000002', 'MIT'),
  ('dcdcc007-0000-0000-0000-000000000003', 'Apache-2.0'),
  ('dcdcc007-0000-0000-0000-000000000004', 'MIT'),
  ('dcdcc008-0000-0000-0000-000000000001', 'MIT'),
  ('dcdcc008-0000-0000-0000-000000000002', 'MIT'),
  ('dcdcc008-0000-0000-0000-000000000003', 'MIT'),
  ('dcdcc008-0000-0000-0000-000000000004', 'LGPL-3.0'),
  ('dcdcc009-0000-0000-0000-000000000001', 'MIT'),
  ('dcdcc009-0000-0000-0000-000000000002', 'Apache-2.0'),
  ('dcdcc00a-0000-0000-0000-000000000001', 'Apache-2.0'),
  ('dcdcc00a-0000-0000-0000-000000000002', 'Apache-2.0'),
  ('dcdcc00b-0000-0000-0000-000000000001', 'Apache-2.0'),
  ('dcdcc00b-0000-0000-0000-000000000002', 'Apache-2.0')
ON CONFLICT (component_id, license_id) DO NOTHING;

-- =============================================================================
-- Step 6: asset_components — links assets to global components
-- (Same components can repeat across assets — that's the blast-radius story.)
-- =============================================================================

DO $$
DECLARE
  v_tenant_id UUID;
BEGIN
  SELECT id INTO v_tenant_id FROM tenants
  WHERE name ILIKE '%org%' OR slug ILIKE '%org%'
  ORDER BY created_at LIMIT 1;

  -- Each row links (asset, component) and copies a few denormalized fields
  -- (name, version, ecosystem, license, purl) so the existing list query
  -- works even before a JOIN. component_id is the FK to global components.

  INSERT INTO asset_components (id, tenant_id, asset_id, component_id, name, version, ecosystem, package_manager,
                                license, purl, dependency_type, is_direct, depth, manifest_file, status)
  VALUES
    -- web-storefront — npm (~30)
    ('dcdc2001-0000-0000-0000-000000000001', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-000000000001', 'react', '18.2.0', 'npm', 'npm', 'MIT', 'pkg:npm/react@18.2.0', 'direct', true, 0, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-000000000002', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-000000000002', 'react-dom', '18.2.0', 'npm', 'npm', 'MIT', 'pkg:npm/react-dom@18.2.0', 'direct', true, 0, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-000000000003', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-000000000003', 'next', '14.1.0', 'npm', 'npm', 'MIT', 'pkg:npm/next@14.1.0', 'direct', true, 0, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-000000000004', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-000000000004', 'axios', '1.6.5', 'npm', 'npm', 'MIT', 'pkg:npm/axios@1.6.5', 'direct', true, 0, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-000000000005', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-000000000005', 'lodash', '4.17.20', 'npm', 'npm', 'MIT', 'pkg:npm/lodash@4.17.20', 'transitive', false, 1, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-000000000006', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-000000000006', 'express', '4.18.2', 'npm', 'npm', 'MIT', 'pkg:npm/express@4.18.2', 'direct', true, 0, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-000000000007', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-000000000007', 'cross-spawn', '7.0.3', 'npm', 'npm', 'MIT', 'pkg:npm/cross-spawn@7.0.3', 'transitive', false, 2, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-000000000008', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-000000000008', 'braces', '3.0.2', 'npm', 'npm', 'MIT', 'pkg:npm/braces@3.0.2', 'transitive', false, 2, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-000000000009', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-000000000009', 'ws', '8.16.0', 'npm', 'npm', 'MIT', 'pkg:npm/ws@8.16.0', 'transitive', false, 1, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-00000000000a', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-00000000000a', 'tar-fs', '2.1.1', 'npm', 'npm', 'MIT', 'pkg:npm/tar-fs@2.1.1', 'transitive', false, 2, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-00000000000b', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-00000000000b', 'ip', '2.0.0', 'npm', 'npm', 'MIT', 'pkg:npm/ip@2.0.0', 'transitive', false, 3, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-00000000000c', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-00000000000c', 'webpack', '5.89.0', 'npm', 'npm', 'MIT', 'pkg:npm/webpack@5.89.0', 'direct', true, 0, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-00000000000d', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-00000000000d', 'typescript', '5.3.3', 'npm', 'npm', 'Apache-2.0', 'pkg:npm/typescript@5.3.3', 'direct', true, 0, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-00000000000e', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-00000000000e', 'eslint', '8.56.0', 'npm', 'npm', 'MIT', 'pkg:npm/eslint@8.56.0', 'direct', true, 0, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-00000000000f', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-00000000001e', 'tailwindcss', '3.4.1', 'npm', 'npm', 'MIT', 'pkg:npm/tailwindcss@3.4.1', 'direct', true, 0, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-000000000010', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-00000000001f', 'zod', '3.22.4', 'npm', 'npm', 'MIT', 'pkg:npm/zod@3.22.4', 'direct', true, 0, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-000000000011', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-000000000019', 'request', '2.88.2', 'npm', 'npm', 'Apache-2.0', 'pkg:npm/request@2.88.2', 'transitive', false, 4, 'package.json', 'deprecated'),
    ('dcdc2001-0000-0000-0000-000000000012', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-00000000001a', 'node-forge', '1.3.1', 'npm', 'npm', 'GPL-2.0', 'pkg:npm/node-forge@1.3.1', 'transitive', false, 3, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-000000000013', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-00000000001b', 'moment', '2.29.4', 'npm', 'npm', 'MIT', 'pkg:npm/moment@2.29.4', 'direct', true, 0, 'package.json', 'deprecated'),
    ('dcdc2001-0000-0000-0000-000000000014', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-00000000001c', 'colors', '1.4.0', 'npm', 'npm', 'MIT', 'pkg:npm/colors@1.4.0', 'transitive', false, 3, 'package.json', 'deprecated'),
    ('dcdc2001-0000-0000-0000-000000000015', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-00000000001d', 'jquery', '3.7.1', 'npm', 'npm', 'MIT', 'pkg:npm/jquery@3.7.1', 'transitive', false, 4, 'package.json', 'active'),
    -- api-gateway — npm (10), composer (4) — REUSES axios, lodash, ws to demo blast radius
    ('dcdc2001-0000-0000-0000-000000000016', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000002', 'dcdcc001-0000-0000-0000-000000000004', 'axios', '1.6.5', 'npm', 'npm', 'MIT', 'pkg:npm/axios@1.6.5', 'direct', true, 0, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-000000000017', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000002', 'dcdcc001-0000-0000-0000-000000000005', 'lodash', '4.17.20', 'npm', 'npm', 'MIT', 'pkg:npm/lodash@4.17.20', 'transitive', false, 2, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-000000000018', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000002', 'dcdcc001-0000-0000-0000-000000000009', 'ws', '8.16.0', 'npm', 'npm', 'MIT', 'pkg:npm/ws@8.16.0', 'transitive', false, 1, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-000000000019', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000002', 'dcdcc001-0000-0000-0000-000000000010', 'fastify', '4.25.2', 'npm', 'npm', 'MIT', 'pkg:npm/fastify@4.25.2', 'direct', true, 0, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-00000000001a', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000002', 'dcdcc001-0000-0000-0000-000000000011', 'jsonwebtoken', '9.0.2', 'npm', 'npm', 'MIT', 'pkg:npm/jsonwebtoken@9.0.2', 'direct', true, 0, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-00000000001b', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000002', 'dcdcc001-0000-0000-0000-000000000012', 'bcrypt', '5.1.1', 'npm', 'npm', 'MIT', 'pkg:npm/bcrypt@5.1.1', 'direct', true, 0, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-00000000001c', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000002', 'dcdcc001-0000-0000-0000-000000000013', 'redis', '4.6.12', 'npm', 'npm', 'MIT', 'pkg:npm/redis@4.6.12', 'direct', true, 0, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-00000000001d', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000002', 'dcdcc001-0000-0000-0000-000000000014', 'pg', '8.11.3', 'npm', 'npm', 'MIT', 'pkg:npm/pg@8.11.3', 'direct', true, 0, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-00000000001e', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000002', 'dcdcc001-0000-0000-0000-000000000015', 'mongoose', '8.1.0', 'npm', 'npm', 'MIT', 'pkg:npm/mongoose@8.1.0', 'direct', true, 0, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-00000000001f', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000002', 'dcdcc001-0000-0000-0000-000000000016', 'socket.io', '4.7.4', 'npm', 'npm', 'MIT', 'pkg:npm/socket.io@4.7.4', 'direct', true, 0, 'package.json', 'active'),
    ('dcdc2001-0000-0000-0000-000000000020', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000002', 'dcdcc006-0000-0000-0000-000000000001', 'symfony/http-foundation', '6.4.2', 'composer', 'composer', 'MIT', 'pkg:composer/symfony/http-foundation@6.4.2', 'direct', true, 0, 'composer.json', 'active'),
    ('dcdc2001-0000-0000-0000-000000000021', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000002', 'dcdcc006-0000-0000-0000-000000000002', 'laravel/framework', '10.41.0', 'composer', 'composer', 'MIT', 'pkg:composer/laravel/framework@10.41.0', 'direct', true, 0, 'composer.json', 'active'),
    ('dcdc2001-0000-0000-0000-000000000022', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000002', 'dcdcc006-0000-0000-0000-000000000003', 'guzzlehttp/guzzle', '7.8.1', 'composer', 'composer', 'MIT', 'pkg:composer/guzzlehttp/guzzle@7.8.1', 'direct', true, 0, 'composer.json', 'active'),
    ('dcdc2001-0000-0000-0000-000000000023', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000002', 'dcdcc006-0000-0000-0000-000000000004', 'monolog/monolog', '3.5.0', 'composer', 'composer', 'MIT', 'pkg:composer/monolog/monolog@3.5.0', 'direct', true, 0, 'composer.json', 'active'),
    -- payment-service — maven (14), nuget (5)
    ('dcdc2002-0000-0000-0000-000000000001', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-000000000001', 'spring-boot-starter-web', '3.2.1', 'maven', 'maven', 'Apache-2.0', 'pkg:maven/org.springframework.boot/spring-boot-starter-web@3.2.1', 'direct', true, 0, 'pom.xml', 'active'),
    ('dcdc2002-0000-0000-0000-000000000002', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-000000000002', 'spring-core', '6.1.2', 'maven', 'maven', 'Apache-2.0', 'pkg:maven/org.springframework/spring-core@6.1.2', 'transitive', false, 1, 'pom.xml', 'active'),
    ('dcdc2002-0000-0000-0000-000000000003', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-000000000003', 'spring-webmvc', '6.0.0', 'maven', 'maven', 'Apache-2.0', 'pkg:maven/org.springframework/spring-webmvc@6.0.0', 'transitive', false, 1, 'pom.xml', 'active'),
    ('dcdc2002-0000-0000-0000-000000000004', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-000000000004', 'log4j-core', '2.14.1', 'maven', 'maven', 'Apache-2.0', 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1', 'transitive', false, 2, 'pom.xml', 'active'),
    ('dcdc2002-0000-0000-0000-000000000005', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-000000000005', 'log4j-api', '2.14.1', 'maven', 'maven', 'Apache-2.0', 'pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1', 'transitive', false, 2, 'pom.xml', 'active'),
    ('dcdc2002-0000-0000-0000-000000000006', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-000000000006', 'jackson-databind', '2.16.1', 'maven', 'maven', 'Apache-2.0', 'pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.16.1', 'transitive', false, 1, 'pom.xml', 'active'),
    ('dcdc2002-0000-0000-0000-000000000007', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-000000000007', 'tomcat-embed-core', '10.1.18', 'maven', 'maven', 'Apache-2.0', 'pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@10.1.18', 'transitive', false, 1, 'pom.xml', 'active'),
    ('dcdc2002-0000-0000-0000-000000000008', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-000000000008', 'netty-all', '4.1.99.Final', 'maven', 'maven', 'Apache-2.0', 'pkg:maven/io.netty/netty-all@4.1.99.Final', 'transitive', false, 2, 'pom.xml', 'active'),
    ('dcdc2002-0000-0000-0000-000000000009', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-000000000009', 'commons-compress', '1.25.0', 'maven', 'maven', 'Apache-2.0', 'pkg:maven/org.apache.commons/commons-compress@1.25.0', 'direct', true, 0, 'pom.xml', 'active'),
    ('dcdc2002-0000-0000-0000-00000000000a', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-00000000000a', 'poi', '5.2.3', 'maven', 'maven', 'Apache-2.0', 'pkg:maven/org.apache.poi/poi@5.2.3', 'direct', true, 0, 'pom.xml', 'active'),
    ('dcdc2002-0000-0000-0000-00000000000b', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-00000000000b', 'guava', '33.0.0-jre', 'maven', 'maven', 'Apache-2.0', 'pkg:maven/com.google.guava/guava@33.0.0-jre', 'direct', true, 0, 'pom.xml', 'active'),
    ('dcdc2002-0000-0000-0000-00000000000c', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-00000000000c', 'activemq-client', '5.17.5', 'maven', 'maven', 'Apache-2.0', 'pkg:maven/org.apache.activemq/activemq-client@5.17.5', 'direct', true, 0, 'pom.xml', 'active'),
    ('dcdc2002-0000-0000-0000-00000000000d', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-00000000000d', 'hibernate-core', '6.4.1.Final', 'maven', 'maven', 'LGPL-2.1', 'pkg:maven/org.hibernate.orm/hibernate-core@6.4.1.Final', 'direct', true, 0, 'pom.xml', 'active'),
    ('dcdc2002-0000-0000-0000-00000000000e', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-00000000000e', 'mysql-connector-j', '8.3.0', 'maven', 'maven', 'GPL-2.0', 'pkg:maven/com.mysql/mysql-connector-j@8.3.0', 'direct', true, 0, 'pom.xml', 'active'),
    ('dcdc2002-0000-0000-0000-00000000000f', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc005-0000-0000-0000-000000000001', 'Microsoft.AspNetCore.App', '8.0.1', 'nuget', 'nuget', 'MIT', 'pkg:nuget/Microsoft.AspNetCore.App@8.0.1', 'direct', true, 0, 'csproj', 'active'),
    ('dcdc2002-0000-0000-0000-000000000010', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc005-0000-0000-0000-000000000002', 'System.Text.Json', '8.0.0', 'nuget', 'nuget', 'MIT', 'pkg:nuget/System.Text.Json@8.0.0', 'transitive', false, 1, 'csproj', 'active'),
    ('dcdc2002-0000-0000-0000-000000000011', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc005-0000-0000-0000-000000000003', 'Newtonsoft.Json', '13.0.3', 'nuget', 'nuget', 'MIT', 'pkg:nuget/Newtonsoft.Json@13.0.3', 'direct', true, 0, 'csproj', 'active'),
    ('dcdc2002-0000-0000-0000-000000000012', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc005-0000-0000-0000-000000000004', 'EntityFrameworkCore', '8.0.1', 'nuget', 'nuget', 'MIT', 'pkg:nuget/Microsoft.EntityFrameworkCore@8.0.1', 'direct', true, 0, 'csproj', 'active'),
    ('dcdc2002-0000-0000-0000-000000000013', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc005-0000-0000-0000-000000000005', 'Serilog', '3.1.1', 'nuget', 'nuget', 'Apache-2.0', 'pkg:nuget/Serilog@3.1.1', 'direct', true, 0, 'csproj', 'active'),
    -- mobile-app (npm RN + cocoapods + gradle + swiftpm)
    ('dcdc2003-0000-0000-0000-000000000001', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000004', 'dcdcc001-0000-0000-0000-000000000017', 'react-native', '0.73.2', 'npm', 'npm', 'MIT', 'pkg:npm/react-native@0.73.2', 'direct', true, 0, 'package.json', 'active'),
    ('dcdc2003-0000-0000-0000-000000000002', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000004', 'dcdcc001-0000-0000-0000-000000000018', 'expo', '50.0.5', 'npm', 'npm', 'MIT', 'pkg:npm/expo@50.0.5', 'direct', true, 0, 'package.json', 'active'),
    ('dcdc2003-0000-0000-0000-000000000003', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000004', 'dcdcc009-0000-0000-0000-000000000001', 'Alamofire', '5.8.1', 'cocoapods', 'cocoapods', 'MIT', 'pkg:cocoapods/Alamofire@5.8.1', 'direct', true, 0, 'Podfile', 'active'),
    ('dcdc2003-0000-0000-0000-000000000004', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000004', 'dcdcc009-0000-0000-0000-000000000002', 'Realm', '10.45.2', 'cocoapods', 'cocoapods', 'Apache-2.0', 'pkg:cocoapods/Realm@10.45.2', 'direct', true, 0, 'Podfile', 'active'),
    ('dcdc2003-0000-0000-0000-000000000005', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000004', 'dcdcc00a-0000-0000-0000-000000000001', 'androidx.compose.ui:ui', '1.6.0', 'gradle', 'gradle', 'Apache-2.0', 'pkg:maven/androidx.compose.ui/ui@1.6.0', 'direct', true, 0, 'build.gradle', 'active'),
    ('dcdc2003-0000-0000-0000-000000000006', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000004', 'dcdcc00a-0000-0000-0000-000000000002', 'com.squareup.retrofit2:retrofit', '2.9.0', 'gradle', 'gradle', 'Apache-2.0', 'pkg:maven/com.squareup.retrofit2/retrofit@2.9.0', 'direct', true, 0, 'build.gradle', 'active'),
    ('dcdc2003-0000-0000-0000-000000000007', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000004', 'dcdcc00b-0000-0000-0000-000000000001', 'swift-collections', '1.0.6', 'swiftpm', 'swiftpm', 'Apache-2.0', 'pkg:swift/apple/swift-collections@1.0.6', 'direct', true, 0, 'Package.swift', 'active'),
    ('dcdc2003-0000-0000-0000-000000000008', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000004', 'dcdcc00b-0000-0000-0000-000000000002', 'swift-nio', '2.62.0', 'swiftpm', 'swiftpm', 'Apache-2.0', 'pkg:swift/apple/swift-nio@2.62.0', 'direct', true, 0, 'Package.swift', 'active'),
    -- iac-infra — pypi + cargo + rubygems
    ('dcdc2004-0000-0000-0000-000000000001', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc003-0000-0000-0000-000000000001', 'requests', '2.31.0', 'pypi', 'pip', 'Apache-2.0', 'pkg:pypi/requests@2.31.0', 'direct', true, 0, 'requirements.txt', 'active'),
    ('dcdc2004-0000-0000-0000-000000000002', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc003-0000-0000-0000-000000000002', 'urllib3', '2.0.7', 'pypi', 'pip', 'MIT', 'pkg:pypi/urllib3@2.0.7', 'transitive', false, 1, 'requirements.txt', 'active'),
    ('dcdc2004-0000-0000-0000-000000000003', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc003-0000-0000-0000-000000000003', 'idna', '3.4', 'pypi', 'pip', 'BSD-3-Clause', 'pkg:pypi/idna@3.4', 'transitive', false, 2, 'requirements.txt', 'active'),
    ('dcdc2004-0000-0000-0000-000000000004', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc003-0000-0000-0000-000000000004', 'jinja2', '3.1.2', 'pypi', 'pip', 'BSD-3-Clause', 'pkg:pypi/jinja2@3.1.2', 'direct', true, 0, 'requirements.txt', 'active'),
    ('dcdc2004-0000-0000-0000-000000000005', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc003-0000-0000-0000-000000000005', 'flask', '3.0.1', 'pypi', 'pip', 'BSD-3-Clause', 'pkg:pypi/flask@3.0.1', 'direct', true, 0, 'requirements.txt', 'active'),
    ('dcdc2004-0000-0000-0000-000000000006', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc003-0000-0000-0000-000000000006', 'werkzeug', '3.0.0', 'pypi', 'pip', 'BSD-3-Clause', 'pkg:pypi/werkzeug@3.0.0', 'transitive', false, 1, 'requirements.txt', 'active'),
    ('dcdc2004-0000-0000-0000-000000000007', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc003-0000-0000-0000-000000000007', 'gunicorn', '21.2.0', 'pypi', 'pip', 'MIT', 'pkg:pypi/gunicorn@21.2.0', 'direct', true, 0, 'requirements.txt', 'active'),
    ('dcdc2004-0000-0000-0000-000000000008', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc003-0000-0000-0000-000000000008', 'django', '4.2.9', 'pypi', 'pip', 'BSD-3-Clause', 'pkg:pypi/django@4.2.9', 'direct', true, 0, 'requirements.txt', 'active'),
    ('dcdc2004-0000-0000-0000-000000000009', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc003-0000-0000-0000-000000000009', 'fastapi', '0.108.0', 'pypi', 'pip', 'MIT', 'pkg:pypi/fastapi@0.108.0', 'direct', true, 0, 'requirements.txt', 'active'),
    ('dcdc2004-0000-0000-0000-00000000000a', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc003-0000-0000-0000-00000000000a', 'python-multipart', '0.0.6', 'pypi', 'pip', 'Apache-2.0', 'pkg:pypi/python-multipart@0.0.6', 'transitive', false, 1, 'requirements.txt', 'active'),
    ('dcdc2004-0000-0000-0000-00000000000b', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc003-0000-0000-0000-00000000000b', 'cryptography', '41.0.7', 'pypi', 'pip', 'Apache-2.0', 'pkg:pypi/cryptography@41.0.7', 'direct', true, 0, 'requirements.txt', 'active'),
    ('dcdc2004-0000-0000-0000-00000000000c', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc003-0000-0000-0000-00000000000c', 'numpy', '1.26.3', 'pypi', 'pip', 'BSD-3-Clause', 'pkg:pypi/numpy@1.26.3', 'direct', true, 0, 'requirements.txt', 'active'),
    ('dcdc2004-0000-0000-0000-00000000000d', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc003-0000-0000-0000-00000000000d', 'pandas', '2.1.4', 'pypi', 'pip', 'BSD-3-Clause', 'pkg:pypi/pandas@2.1.4', 'direct', true, 0, 'requirements.txt', 'active'),
    ('dcdc2004-0000-0000-0000-00000000000e', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc003-0000-0000-0000-00000000000e', 'sqlalchemy', '2.0.25', 'pypi', 'pip', 'MIT', 'pkg:pypi/sqlalchemy@2.0.25', 'direct', true, 0, 'requirements.txt', 'active'),
    ('dcdc2004-0000-0000-0000-00000000000f', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc003-0000-0000-0000-00000000000f', 'boto3', '1.34.14', 'pypi', 'pip', 'Apache-2.0', 'pkg:pypi/boto3@1.34.14', 'direct', true, 0, 'requirements.txt', 'active'),
    ('dcdc2004-0000-0000-0000-000000000010', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc007-0000-0000-0000-000000000001', 'tokio', '1.35.1', 'cargo', 'cargo', 'MIT', 'pkg:cargo/tokio@1.35.1', 'direct', true, 0, 'Cargo.toml', 'active'),
    ('dcdc2004-0000-0000-0000-000000000011', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc007-0000-0000-0000-000000000002', 'serde', '1.0.195', 'cargo', 'cargo', 'MIT', 'pkg:cargo/serde@1.0.195', 'direct', true, 0, 'Cargo.toml', 'active'),
    ('dcdc2004-0000-0000-0000-000000000012', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc007-0000-0000-0000-000000000003', 'openssl', '0.10.62', 'cargo', 'cargo', 'Apache-2.0', 'pkg:cargo/openssl@0.10.62', 'direct', true, 0, 'Cargo.toml', 'active'),
    ('dcdc2004-0000-0000-0000-000000000013', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc007-0000-0000-0000-000000000004', 'reqwest', '0.11.23', 'cargo', 'cargo', 'MIT', 'pkg:cargo/reqwest@0.11.23', 'direct', true, 0, 'Cargo.toml', 'active'),
    ('dcdc2004-0000-0000-0000-000000000014', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc008-0000-0000-0000-000000000001', 'rails', '7.1.2', 'rubygems', 'gem', 'MIT', 'pkg:gem/rails@7.1.2', 'direct', true, 0, 'Gemfile', 'active'),
    ('dcdc2004-0000-0000-0000-000000000015', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc008-0000-0000-0000-000000000002', 'rack', '3.0.8', 'rubygems', 'gem', 'MIT', 'pkg:gem/rack@3.0.8', 'transitive', false, 1, 'Gemfile', 'active'),
    ('dcdc2004-0000-0000-0000-000000000016', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc008-0000-0000-0000-000000000003', 'sinatra', '4.0.0', 'rubygems', 'gem', 'MIT', 'pkg:gem/sinatra@4.0.0', 'direct', true, 0, 'Gemfile', 'active'),
    ('dcdc2004-0000-0000-0000-000000000017', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc008-0000-0000-0000-000000000004', 'sidekiq', '7.2.1', 'rubygems', 'gem', 'LGPL-3.0', 'pkg:gem/sidekiq@7.2.1', 'direct', true, 0, 'Gemfile', 'active'),
    -- k8s-prod — Go components
    ('dcdc2005-0000-0000-0000-000000000001', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000006', 'dcdcc004-0000-0000-0000-000000000001', 'github.com/gin-gonic/gin', '1.9.1', 'go', 'go', 'MIT', 'pkg:golang/github.com/gin-gonic/gin@1.9.1', 'direct', true, 0, 'go.mod', 'active'),
    ('dcdc2005-0000-0000-0000-000000000002', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000006', 'dcdcc004-0000-0000-0000-000000000002', 'google.golang.org/protobuf', '1.31.0', 'go', 'go', 'BSD-3-Clause', 'pkg:golang/google.golang.org/protobuf@1.31.0', 'transitive', false, 1, 'go.mod', 'active'),
    ('dcdc2005-0000-0000-0000-000000000003', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000006', 'dcdcc004-0000-0000-0000-000000000003', 'golang.org/x/crypto', '0.18.0', 'go', 'go', 'BSD-3-Clause', 'pkg:golang/golang.org/x/crypto@0.18.0', 'direct', true, 0, 'go.mod', 'active'),
    ('dcdc2005-0000-0000-0000-000000000004', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000006', 'dcdcc004-0000-0000-0000-000000000004', 'github.com/moby/moby', '24.0.7', 'go', 'go', 'Apache-2.0', 'pkg:golang/github.com/moby/moby@24.0.7', 'transitive', false, 1, 'go.mod', 'active'),
    ('dcdc2005-0000-0000-0000-000000000005', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000006', 'dcdcc004-0000-0000-0000-000000000005', 'k8s.io/client-go', '0.29.1', 'go', 'go', 'Apache-2.0', 'pkg:golang/k8s.io/client-go@0.29.1', 'direct', true, 0, 'go.mod', 'active'),
    ('dcdc2005-0000-0000-0000-000000000006', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000006', 'dcdcc004-0000-0000-0000-000000000006', 'k8s.io/api', '0.29.1', 'go', 'go', 'Apache-2.0', 'pkg:golang/k8s.io/api@0.29.1', 'direct', true, 0, 'go.mod', 'active'),
    ('dcdc2005-0000-0000-0000-000000000007', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000006', 'dcdcc004-0000-0000-0000-000000000007', 'github.com/opencontainers/runc', '1.1.10', 'go', 'go', 'Apache-2.0', 'pkg:golang/github.com/opencontainers/runc@1.1.10', 'transitive', false, 2, 'go.mod', 'active'),
    ('dcdc2005-0000-0000-0000-000000000008', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000006', 'dcdcc004-0000-0000-0000-000000000008', 'github.com/spf13/cobra', '1.8.0', 'go', 'go', 'Apache-2.0', 'pkg:golang/github.com/spf13/cobra@1.8.0', 'direct', true, 0, 'go.mod', 'active'),
    ('dcdc2005-0000-0000-0000-000000000009', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000006', 'dcdcc004-0000-0000-0000-000000000009', 'go.etcd.io/etcd/client/v3', '3.5.11', 'go', 'go', 'Apache-2.0', 'pkg:golang/go.etcd.io/etcd/client/v3@3.5.11', 'direct', true, 0, 'go.mod', 'active')
  ON CONFLICT (id) DO NOTHING;

  RAISE NOTICE 'Inserted asset_components: %', (SELECT COUNT(*) FROM asset_components WHERE tenant_id = v_tenant_id AND id::text LIKE 'dcdc2%');

  -- ---------------------------------------------------------------------------
  -- Step 7: Findings — link assets × global_components × CVEs (~50)
  -- findings.component_id references components(id) (global, not asset_components)
  -- ---------------------------------------------------------------------------
  INSERT INTO findings (id, tenant_id, asset_id, component_id, vulnerability_id,
                        source, tool_name, tool_version, message, severity,
                        cvss_score, cve_id, status, fingerprint, finding_type,
                        is_internet_accessible, exposure_vector, remedy_available,
                        first_detected_at, last_seen_at)
  VALUES
  ('dcdc3001-0000-0000-0000-000000000001', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-000000000004', 'dcdcaaaa-0000-0000-0000-000000000001',
    'sca', 'Trivy', '0.48.3', 'Log4j2 RCE (Log4Shell) detected in payment-service', 'critical', 10.0, 'CVE-2021-44228', 'new',
    md5('dcdc3001-1' || v_tenant_id::text), 'vulnerability', false, 'network', true, NOW() - INTERVAL '12 days', NOW()),
  ('dcdc3001-0000-0000-0000-000000000002', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-000000000005', 'dcdcaaaa-0000-0000-0000-000000000001',
    'sca', 'Trivy', '0.48.3', 'Log4j-api transitive vulnerability (Log4Shell)', 'critical', 10.0, 'CVE-2021-44228', 'confirmed',
    md5('dcdc3001-2' || v_tenant_id::text), 'vulnerability', false, 'network', true, NOW() - INTERVAL '12 days', NOW()),
  ('dcdc3001-0000-0000-0000-000000000003', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-000000000003', 'dcdcaaaa-0000-0000-0000-000000000002',
    'sca', 'Trivy', '0.48.3', 'Spring Framework RCE (Spring4Shell)', 'critical', 9.8, 'CVE-2022-22965', 'new',
    md5('dcdc3001-3' || v_tenant_id::text), 'vulnerability', false, 'network', true, NOW() - INTERVAL '8 days', NOW()),
  ('dcdc3001-0000-0000-0000-000000000004', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000006', NULL, 'dcdcaaaa-0000-0000-0000-000000000004',
    'container', 'Grype', '0.74.0', 'XZ Utils backdoor (liblzma 5.6.0) in node base image', 'critical', 10.0, 'CVE-2024-3094', 'in_progress',
    md5('dcdc3001-4' || v_tenant_id::text), 'vulnerability', false, 'local', true, NOW() - INTERVAL '5 days', NOW()),
  ('dcdc3001-0000-0000-0000-000000000005', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000006', 'dcdcc004-0000-0000-0000-000000000007', 'dcdcaaaa-0000-0000-0000-00000000002c',
    'container', 'Grype', '0.74.0', 'runc 1.1.10 container escape (Leaky Vessels)', 'high', 8.6, 'CVE-2024-21626', 'new',
    md5('dcdc3001-5' || v_tenant_id::text), 'vulnerability', false, 'local', true, NOW() - INTERVAL '15 days', NOW()),
  ('dcdc3001-0000-0000-0000-000000000006', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-000000000007', 'dcdcaaaa-0000-0000-0000-00000000000b',
    'sca', 'npm-audit', '10.2.4', 'cross-spawn ReDoS vulnerability', 'high', 7.5, 'CVE-2024-21538', 'new',
    md5('dcdc3001-6' || v_tenant_id::text), 'vulnerability', true, 'network', true, NOW() - INTERVAL '3 days', NOW()),
  ('dcdc3001-0000-0000-0000-000000000007', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-000000000008', 'dcdcaaaa-0000-0000-0000-00000000000c',
    'sca', 'npm-audit', '10.2.4', 'braces uncontrolled resource consumption', 'high', 7.5, 'CVE-2024-4068', 'new',
    md5('dcdc3001-7' || v_tenant_id::text), 'vulnerability', true, 'network', true, NOW() - INTERVAL '7 days', NOW()),
  -- Same axios CVE on TWO assets — demonstrates blast radius
  ('dcdc3001-0000-0000-0000-000000000008', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-000000000004', 'dcdcaaaa-0000-0000-0000-000000000011',
    'sca', 'npm-audit', '10.2.4', 'axios SSRF via protocol-relative URL (web-storefront)', 'high', 7.5, 'CVE-2024-39338', 'new',
    md5('dcdc3001-8' || v_tenant_id::text), 'vulnerability', true, 'network', true, NOW() - INTERVAL '4 days', NOW()),
  ('dcdc3001-0000-0000-0000-000000000009', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000002', 'dcdcc001-0000-0000-0000-000000000004', 'dcdcaaaa-0000-0000-0000-000000000011',
    'sca', 'npm-audit', '10.2.4', 'axios SSRF via protocol-relative URL (api-gateway)', 'high', 7.5, 'CVE-2024-39338', 'confirmed',
    md5('dcdc3001-9' || v_tenant_id::text), 'vulnerability', true, 'network', true, NOW() - INTERVAL '4 days', NOW()),
  -- ws DoS on two assets
  ('dcdc3001-0000-0000-0000-00000000000a', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-000000000009', 'dcdcaaaa-0000-0000-0000-00000000000d',
    'sca', 'npm-audit', '10.2.4', 'ws WebSocket DoS via crafted headers (web)', 'high', 7.5, 'CVE-2024-37890', 'new',
    md5('dcdc3001-a' || v_tenant_id::text), 'vulnerability', true, 'network', true, NOW() - INTERVAL '4 days', NOW()),
  ('dcdc3001-0000-0000-0000-00000000000b', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000002', 'dcdcc001-0000-0000-0000-000000000009', 'dcdcaaaa-0000-0000-0000-00000000000d',
    'sca', 'npm-audit', '10.2.4', 'ws WebSocket DoS via crafted headers (api)', 'high', 7.5, 'CVE-2024-37890', 'in_progress',
    md5('dcdc3001-b' || v_tenant_id::text), 'vulnerability', true, 'network', true, NOW() - INTERVAL '4 days', NOW()),
  ('dcdc3001-0000-0000-0000-00000000000c', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-00000000000a', 'dcdcaaaa-0000-0000-0000-00000000000e',
    'sca', 'npm-audit', '10.2.4', 'tar-fs path traversal allows arbitrary write', 'high', 8.1, 'CVE-2024-24790', 'in_progress',
    md5('dcdc3001-c' || v_tenant_id::text), 'vulnerability', true, 'network', true, NOW() - INTERVAL '6 days', NOW()),
  ('dcdc3001-0000-0000-0000-00000000000d', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-00000000000b', 'dcdcaaaa-0000-0000-0000-00000000000f',
    'sca', 'npm-audit', '10.2.4', 'ip package isPublic() SSRF bypass', 'high', 8.1, 'CVE-2024-29415', 'new',
    md5('dcdc3001-d' || v_tenant_id::text), 'vulnerability', true, 'network', true, NOW() - INTERVAL '2 days', NOW()),
  ('dcdc3001-0000-0000-0000-00000000000e', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000001', 'dcdcc001-0000-0000-0000-00000000000c', 'dcdcaaaa-0000-0000-0000-000000000010',
    'sca', 'npm-audit', '10.2.4', 'webpack dev-server XSS in error page', 'medium', 6.4, 'CVE-2024-43788', 'new',
    md5('dcdc3001-e' || v_tenant_id::text), 'vulnerability', true, 'network', true, NOW() - INTERVAL '9 days', NOW()),
  -- pypi
  ('dcdc3001-0000-0000-0000-00000000000f', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc003-0000-0000-0000-000000000003', 'dcdcaaaa-0000-0000-0000-000000000013',
    'sca', 'pip-audit', '2.7.0', 'idna quadratic complexity attack', 'high', 7.5, 'CVE-2024-3651', 'new',
    md5('dcdc3001-f' || v_tenant_id::text), 'vulnerability', false, 'network', true, NOW() - INTERVAL '5 days', NOW()),
  ('dcdc3001-0000-0000-0000-000000000010', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc003-0000-0000-0000-000000000001', 'dcdcaaaa-0000-0000-0000-000000000014',
    'sca', 'pip-audit', '2.7.0', 'requests Session.verify=False persists across calls', 'medium', 5.6, 'CVE-2024-35195', 'new',
    md5('dcdc3001-10' || v_tenant_id::text), 'vulnerability', false, 'network', true, NOW() - INTERVAL '11 days', NOW()),
  ('dcdc3001-0000-0000-0000-000000000011', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc003-0000-0000-0000-000000000002', 'dcdcaaaa-0000-0000-0000-000000000015',
    'sca', 'pip-audit', '2.7.0', 'urllib3 proxy-authorization header leak after redirect', 'medium', 4.4, 'CVE-2024-37891', 'new',
    md5('dcdc3001-11' || v_tenant_id::text), 'vulnerability', false, 'network', true, NOW() - INTERVAL '10 days', NOW()),
  ('dcdc3001-0000-0000-0000-000000000012', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc003-0000-0000-0000-000000000004', 'dcdcaaaa-0000-0000-0000-000000000016',
    'sca', 'pip-audit', '2.7.0', 'Jinja2 xmlattr filter XSS', 'medium', 6.1, 'CVE-2024-22195', 'new',
    md5('dcdc3001-12' || v_tenant_id::text), 'vulnerability', false, 'network', true, NOW() - INTERVAL '14 days', NOW()),
  ('dcdc3001-0000-0000-0000-000000000013', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc003-0000-0000-0000-000000000007', 'dcdcaaaa-0000-0000-0000-000000000017',
    'sca', 'pip-audit', '2.7.0', 'gunicorn HTTP request smuggling via Transfer-Encoding', 'high', 7.5, 'CVE-2024-1135', 'in_progress',
    md5('dcdc3001-13' || v_tenant_id::text), 'vulnerability', true, 'network', true, NOW() - INTERVAL '8 days', NOW()),
  ('dcdc3001-0000-0000-0000-000000000014', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc003-0000-0000-0000-000000000006', 'dcdcaaaa-0000-0000-0000-000000000019',
    'sca', 'pip-audit', '2.7.0', 'Werkzeug multipart parser unbounded memory', 'high', 7.5, 'CVE-2024-49767', 'new',
    md5('dcdc3001-14' || v_tenant_id::text), 'vulnerability', false, 'network', true, NOW() - INTERVAL '4 days', NOW()),
  ('dcdc3001-0000-0000-0000-000000000015', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc003-0000-0000-0000-00000000000a', 'dcdcaaaa-0000-0000-0000-00000000001a',
    'sca', 'pip-audit', '2.7.0', 'python-multipart Content-Type ReDoS', 'high', 7.5, 'CVE-2024-24762', 'new',
    md5('dcdc3001-15' || v_tenant_id::text), 'vulnerability', false, 'network', true, NOW() - INTERVAL '6 days', NOW()),
  -- maven
  ('dcdc3001-0000-0000-0000-000000000016', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-000000000002', 'dcdcaaaa-0000-0000-0000-00000000001c',
    'sca', 'Trivy', '0.48.3', 'Spring Framework UriComponentsBuilder open redirect/SSRF', 'high', 8.1, 'CVE-2024-22243', 'new',
    md5('dcdc3001-16' || v_tenant_id::text), 'vulnerability', false, 'network', true, NOW() - INTERVAL '7 days', NOW()),
  ('dcdc3001-0000-0000-0000-000000000017', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-00000000000a', 'dcdcaaaa-0000-0000-0000-00000000001d',
    'sca', 'Trivy', '0.48.3', 'Apache POI HSLF resource exhaustion', 'medium', 5.5, 'CVE-2024-29133', 'new',
    md5('dcdc3001-17' || v_tenant_id::text), 'vulnerability', false, 'local', true, NOW() - INTERVAL '12 days', NOW()),
  ('dcdc3001-0000-0000-0000-000000000018', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-000000000009', 'dcdcaaaa-0000-0000-0000-00000000001e',
    'sca', 'Trivy', '0.48.3', 'Apache Commons Compress DUMP file DoS', 'high', 7.5, 'CVE-2024-25710', 'new',
    md5('dcdc3001-18' || v_tenant_id::text), 'vulnerability', false, 'network', true, NOW() - INTERVAL '5 days', NOW()),
  ('dcdc3001-0000-0000-0000-000000000019', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-000000000008', 'dcdcaaaa-0000-0000-0000-00000000001b',
    'sca', 'Trivy', '0.48.3', 'Netty affected by HTTP/2 Rapid Reset DDoS', 'high', 7.5, 'CVE-2023-44487', 'confirmed',
    md5('dcdc3001-19' || v_tenant_id::text), 'vulnerability', false, 'network', true, NOW() - INTERVAL '20 days', NOW()),
  ('dcdc3001-0000-0000-0000-00000000001a', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-000000000007', 'dcdcaaaa-0000-0000-0000-000000000020',
    'sca', 'Trivy', '0.48.3', 'Tomcat information disclosure in chunked encoding', 'medium', 5.3, 'CVE-2024-21733', 'new',
    md5('dcdc3001-1a' || v_tenant_id::text), 'vulnerability', false, 'network', true, NOW() - INTERVAL '15 days', NOW()),
  ('dcdc3001-0000-0000-0000-00000000001b', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc002-0000-0000-0000-00000000000c', 'dcdcaaaa-0000-0000-0000-000000000008',
    'sca', 'Trivy', '0.48.3', 'Apache ActiveMQ OpenWire deserialization RCE', 'critical', 10.0, 'CVE-2023-46604', 'in_progress',
    md5('dcdc3001-1b' || v_tenant_id::text), 'vulnerability', false, 'network', true, NOW() - INTERVAL '25 days', NOW()),
  -- go
  ('dcdc3001-0000-0000-0000-00000000001c', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000006', 'dcdcc004-0000-0000-0000-000000000002', 'dcdcaaaa-0000-0000-0000-000000000021',
    'sca', 'govulncheck', '1.1.0', 'protobuf json unmarshal infinite loop', 'high', 7.5, 'CVE-2024-24786', 'new',
    md5('dcdc3001-1c' || v_tenant_id::text), 'vulnerability', false, 'network', true, NOW() - INTERVAL '5 days', NOW()),
  ('dcdc3001-0000-0000-0000-00000000001d', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000006', 'dcdcc004-0000-0000-0000-000000000003', 'dcdcaaaa-0000-0000-0000-000000000024',
    'sca', 'govulncheck', '1.1.0', 'golang.org/x/crypto/ssh authorization bypass', 'critical', 9.1, 'CVE-2024-45337', 'in_progress',
    md5('dcdc3001-1d' || v_tenant_id::text), 'vulnerability', false, 'network', true, NOW() - INTERVAL '3 days', NOW()),
  ('dcdc3001-0000-0000-0000-00000000001e', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000006', 'dcdcc004-0000-0000-0000-000000000004', 'dcdcaaaa-0000-0000-0000-000000000023',
    'sca', 'govulncheck', '1.1.0', 'Moby BuildKit classic builder cache poisoning', 'medium', 6.9, 'CVE-2024-24557', 'new',
    md5('dcdc3001-1e' || v_tenant_id::text), 'vulnerability', false, 'local', true, NOW() - INTERVAL '11 days', NOW()),
  -- nuget
  ('dcdc3001-0000-0000-0000-00000000001f', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000003', 'dcdcc005-0000-0000-0000-000000000002', 'dcdcaaaa-0000-0000-0000-000000000026',
    'sca', 'Trivy', '0.48.3', '.NET System.Text.Json DoS via crafted JSON', 'high', 7.5, 'CVE-2024-30105', 'new',
    md5('dcdc3001-1f' || v_tenant_id::text), 'vulnerability', false, 'network', true, NOW() - INTERVAL '9 days', NOW()),
  -- composer
  ('dcdc3001-0000-0000-0000-000000000020', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000002', 'dcdcc006-0000-0000-0000-000000000001', 'dcdcaaaa-0000-0000-0000-000000000029',
    'sca', 'Trivy', '0.48.3', 'Symfony HttpFoundation BinaryFileResponse path traversal', 'high', 7.5, 'CVE-2024-32465', 'new',
    md5('dcdc3001-20' || v_tenant_id::text), 'vulnerability', true, 'network', true, NOW() - INTERVAL '6 days', NOW()),
  -- rubygems
  ('dcdc3001-0000-0000-0000-000000000021', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc008-0000-0000-0000-000000000002', 'dcdcaaaa-0000-0000-0000-00000000002a',
    'sca', 'bundle-audit', '0.9.1', 'Rack URI parser ReDoS via Range header', 'high', 7.5, 'CVE-2024-26146', 'new',
    md5('dcdc3001-21' || v_tenant_id::text), 'vulnerability', false, 'network', true, NOW() - INTERVAL '8 days', NOW()),
  -- cargo
  ('dcdc3001-0000-0000-0000-000000000022', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', 'dcdcc007-0000-0000-0000-000000000003', 'dcdcaaaa-0000-0000-0000-000000000031',
    'sca', 'cargo-audit', '0.20.0', 'OpenSSL TLS 1.3 unbounded memory growth', 'medium', 5.9, 'CVE-2024-2511', 'new',
    md5('dcdc3001-22' || v_tenant_id::text), 'vulnerability', false, 'network', true, NOW() - INTERVAL '10 days', NOW()),
  -- container scanners (no component link)
  ('dcdc3001-0000-0000-0000-000000000023', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000006', NULL, 'dcdcaaaa-0000-0000-0000-000000000009',
    'container', 'Grype', '0.74.0', 'OpenSSH regreSSHion RCE in node base image', 'critical', 8.1, 'CVE-2024-6387', 'new',
    md5('dcdc3001-23' || v_tenant_id::text), 'vulnerability', false, 'network', true, NOW() - INTERVAL '7 days', NOW()),
  ('dcdc3001-0000-0000-0000-000000000024', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000006', NULL, 'dcdcaaaa-0000-0000-0000-00000000002d',
    'container', 'Grype', '0.74.0', 'BuildKit cache mount privilege escalation', 'high', 8.7, 'CVE-2024-23652', 'in_progress',
    md5('dcdc3001-24' || v_tenant_id::text), 'vulnerability', false, 'local', true, NOW() - INTERVAL '14 days', NOW()),
  ('dcdc3001-0000-0000-0000-000000000025', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000006', 'dcdcc004-0000-0000-0000-000000000005', 'dcdcaaaa-0000-0000-0000-00000000002f',
    'iac', 'Checkov', '3.2.0', 'Kubernetes gitRepo volume RCE risk', 'critical', 8.1, 'CVE-2024-10220', 'new',
    md5('dcdc3001-25' || v_tenant_id::text), 'vulnerability', false, 'network', true, NOW() - INTERVAL '2 days', NOW()),
  ('dcdc3001-0000-0000-0000-000000000026', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000006', NULL, 'dcdcaaaa-0000-0000-0000-000000000030',
    'container', 'Grype', '0.74.0', 'BIND9 KeyTrap DNSSEC DoS in cluster image', 'high', 7.5, 'CVE-2023-50387', 'new',
    md5('dcdc3001-26' || v_tenant_id::text), 'vulnerability', false, 'network', true, NOW() - INTERVAL '4 days', NOW()),
  -- archived for variety
  ('dcdc3001-0000-0000-0000-000000000027', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', NULL, 'dcdcaaaa-0000-0000-0000-000000000005',
    'easm', 'Nuclei', '3.1.4', 'Confluence privilege escalation detected on repo wiki host', 'critical', 10.0, 'CVE-2023-22515', 'false_positive',
    md5('dcdc3001-27' || v_tenant_id::text), 'vulnerability', true, 'network', true, NOW() - INTERVAL '40 days', NOW()),
  ('dcdc3001-0000-0000-0000-000000000028', v_tenant_id, 'dcdc1111-0000-0000-0000-000000000005', NULL, 'dcdcaaaa-0000-0000-0000-00000000000a',
    'easm', 'Nuclei', '3.1.4', 'Jenkins arbitrary file read detected on CI host', 'critical', 9.8, 'CVE-2024-23897', 'resolved',
    md5('dcdc3001-28' || v_tenant_id::text), 'vulnerability', true, 'network', true, NOW() - INTERVAL '60 days', NOW() - INTERVAL '20 days')
  ON CONFLICT (id) DO NOTHING;

  RAISE NOTICE 'Inserted findings: %', (SELECT COUNT(*) FROM findings WHERE tenant_id = v_tenant_id AND id::text LIKE 'dcdc3%');

  -- ---------------------------------------------------------------------------
  -- Step 8: Recompute aggregated columns on asset_components
  -- ---------------------------------------------------------------------------
  UPDATE asset_components ac
  SET
    vulnerability_count = COALESCE(agg.cnt, 0),
    has_known_vulnerabilities = (COALESCE(agg.cnt, 0) > 0),
    highest_severity = agg.max_sev,
    risk_score = LEAST(100, COALESCE(agg.cnt, 0) * 15
                            + CASE agg.max_sev
                                WHEN 'critical' THEN 40
                                WHEN 'high'     THEN 25
                                WHEN 'medium'   THEN 10
                                WHEN 'low'      THEN 3
                                ELSE 0
                              END)
  FROM (
    SELECT f.component_id,
           ac2.id AS ac_id,
           COUNT(*) FILTER (WHERE f.status IN ('new','confirmed','in_progress')) AS cnt,
           (
             ARRAY['critical','high','medium','low','info','none']::text[]
           )[
             LEAST(
               COALESCE(MIN(CASE f.severity
                              WHEN 'critical' THEN 1
                              WHEN 'high'     THEN 2
                              WHEN 'medium'   THEN 3
                              WHEN 'low'      THEN 4
                              WHEN 'info'     THEN 5
                              ELSE 6 END
                       ) FILTER (WHERE f.status IN ('new','confirmed','in_progress')), 6),
               6
             )
           ] AS max_sev
    FROM findings f
    JOIN asset_components ac2
      ON ac2.tenant_id = f.tenant_id
     AND ac2.asset_id  = f.asset_id
     AND ac2.component_id = f.component_id
    WHERE f.tenant_id = v_tenant_id
      AND f.component_id IS NOT NULL
    GROUP BY f.component_id, ac2.id
  ) agg
  WHERE ac.id = agg.ac_id
    AND ac.tenant_id = v_tenant_id;

  -- Also update global components.vulnerability_count to count distinct CVEs
  UPDATE components c
  SET vulnerability_count = COALESCE(agg.cnt, c.vulnerability_count)
  FROM (
    SELECT component_id, COUNT(DISTINCT vulnerability_id) AS cnt
    FROM findings
    WHERE tenant_id = v_tenant_id
      AND component_id IS NOT NULL
      AND vulnerability_id IS NOT NULL
      AND status IN ('new','confirmed','in_progress')
    GROUP BY component_id
  ) agg
  WHERE c.id = agg.component_id;

  RAISE NOTICE '=== Demo Seed Complete ===';
  RAISE NOTICE 'Tenant: %', v_tenant_id;
  RAISE NOTICE 'CVEs (global): %',     (SELECT COUNT(*) FROM vulnerabilities WHERE id::text LIKE 'dcdcaaaa-%');
  RAISE NOTICE 'Components (global): %', (SELECT COUNT(*) FROM components WHERE id::text LIKE 'dcdcc%');
  RAISE NOTICE 'Assets: %',            (SELECT COUNT(*) FROM assets WHERE tenant_id = v_tenant_id AND id::text LIKE 'dcdc1111-%');
  RAISE NOTICE 'asset_components: %',  (SELECT COUNT(*) FROM asset_components WHERE tenant_id = v_tenant_id AND id::text LIKE 'dcdc2%');
  RAISE NOTICE 'Findings: %',          (SELECT COUNT(*) FROM findings WHERE tenant_id = v_tenant_id AND id::text LIKE 'dcdc3%');
  RAISE NOTICE 'Vulnerable components (per-asset): %', (SELECT COUNT(*) FROM asset_components WHERE tenant_id = v_tenant_id AND has_known_vulnerabilities = true);
END $$;