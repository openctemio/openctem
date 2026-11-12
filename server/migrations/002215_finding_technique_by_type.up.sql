-- A trivy report carries three capabilities (dependencies, misconfigurations,
-- secrets) and its findings were all filed under the first one, so every
-- misconfiguration and secret it found reads "SCA". The technique of a
-- finding is first-writer (findings.source is never rewritten by a later
-- sighting), so ingest fixed for new findings leaves the old rows wrong.
-- A misconfiguration is infrastructure as code and a secret is secret
-- detection whatever the report said: relabel the rows filed as SCA.
UPDATE findings SET source = 'iac'
WHERE source = 'sca' AND finding_type = 'misconfiguration';

UPDATE findings SET source = 'secret'
WHERE source = 'sca' AND finding_type = 'secret';
