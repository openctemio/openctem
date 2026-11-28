-- One name per framework for control tests: "cis", "CIS" and "CIS Controls"
-- were stored apart and showed as separate frameworks. The keys match
-- simulation.CanonicalFramework (lower case, letters and digits only).
UPDATE control_tests SET framework = canon.name, updated_at = NOW()
FROM (VALUES
    ('nistcsf', 'NIST CSF'),
    ('nist', 'NIST CSF'),
    ('iso27001', 'ISO 27001'),
    ('soc2', 'SOC 2'),
    ('cis', 'CIS Controls'),
    ('ciscontrols', 'CIS Controls'),
    ('pcidss', 'PCI DSS'),
    ('pci', 'PCI DSS'),
    ('hipaa', 'HIPAA'),
    ('mitreattack', 'MITRE ATT&CK'),
    ('owaspasvs', 'OWASP ASVS'),
    ('custom', 'Custom')
) AS canon(key, name)
WHERE lower(regexp_replace(control_tests.framework, '[^[:alnum:]]', '', 'g')) = canon.key
  AND control_tests.framework <> canon.name;
