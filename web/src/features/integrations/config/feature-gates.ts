/**
 * Web feature gates for integrations.
 *
 * TENABLE_CONNECTOR_ENABLED: the Tenable.sc connector (api RFC-047) runs as
 * its own image, ghcr.io/openctemio/connector-tenable (source:
 * openctemio/connector-tenable), paired with the platform like a sensor. It is
 * on, as Beta: Settings > Integrations > Vulnerability scanners shows the
 * connectors, the coverage panel and the connect/edit dialog, and the scan
 * wizard offers Tenable.sc scans. Keep it equal to the API's
 * integration.TenableConnectorEnabled; while false, the page shows only the
 * .nessus import and paused rows.
 */
export const TENABLE_CONNECTOR_ENABLED = true
