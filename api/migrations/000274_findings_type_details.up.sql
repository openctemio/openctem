-- Type-specific facts of a finding that have no column of their own: a secret's
-- masked preview, salted fingerprint, scopes, rotation and history facts; a
-- misconfiguration's policy name and cause; a compliance control's framework
-- version and description; a web3 function selector and bytecode offset.
--
-- One typed JSON document per finding, written only by the API from Go
-- structs (pkg/domain/vulnerability/type_details_doc.go):
--   {"v": 1, "secret": {...}} | {"v": 1, "misconfig": {...}} | ...
-- It never contains a secret value: only a preview with at most the first and
-- last 4 characters, and an HMAC fingerprint.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS type_details JSONB;

ALTER TABLE findings DROP CONSTRAINT IF EXISTS chk_findings_type_details_shape;
ALTER TABLE findings ADD CONSTRAINT chk_findings_type_details_shape CHECK (
    type_details IS NULL OR (
        jsonb_typeof(type_details) = 'object'
        AND (type_details ->> 'v') IS NOT NULL
        AND pg_column_size(type_details) <= 32768
    )
);

COMMENT ON COLUMN findings.type_details IS
    'Typed, versioned type-specific facts without a column ({"v":1,"secret"|"misconfig"|"compliance"|"web3":{...}}). Never holds a secret value.';
