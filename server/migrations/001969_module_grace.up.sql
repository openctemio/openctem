-- Read-only grace after an organization loses a module (RFC-064 §4.4):
-- for 30 days it keeps read access (and export) to the module's data, writes
-- are refused and the module's jobs stop. Started when a plan change, a plan
-- mapping change or a deny removes a module; an expired trial grant gives
-- the same grace from its expiry without a row. New, empty table.

CREATE TABLE tenant_module_grace (
    tenant_id       uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    module_id       character varying(50) NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
    read_only_until timestamp with time zone NOT NULL,
    started_at      timestamp with time zone NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, module_id)
);
