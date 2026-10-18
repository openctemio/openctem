-- An organization's own sensor products (api/docs/rfcs/RFC-037 §13): the
-- latest and minimum release an organization records for a sensor product it
-- builds itself on sdk-go, so its sensors get "update available" and
-- "unsupported" verdicts. Used only for that organization's own verdicts;
-- first-party product names (openctemio-*) are refused.
--
-- Live impact: a new, empty table.

CREATE TABLE IF NOT EXISTS tenant_sensor_products (
    tenant_id      uuid        NOT NULL,
    product        varchar(64) NOT NULL,
    latest_version varchar(32),
    min_version    varchar(32),
    updated_by     uuid,
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_tenant_sensor_products PRIMARY KEY (tenant_id, product),
    CONSTRAINT fk_tenant_sensor_products_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_sensor_products_updated_by FOREIGN KEY (updated_by)
        REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT chk_tenant_sensor_products_product CHECK (
        product ~ '^[a-z0-9][a-z0-9._-]{0,63}$' AND product NOT LIKE 'openctemio-%'),
    CONSTRAINT chk_tenant_sensor_products_latest CHECK (
        latest_version IS NULL OR latest_version ~ '^v[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$'),
    CONSTRAINT chk_tenant_sensor_products_min CHECK (
        min_version IS NULL OR min_version ~ '^v[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$')
);

COMMENT ON TABLE tenant_sensor_products IS
    'Release lines an organization records for its own sensor products (latest, min); only that organization''s sensor verdicts read them.';
