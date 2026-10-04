/**
 * Web feature gates for half-built integrations.
 *
 * TENABLE_CONNECTOR_ENABLED mirrors the API's integration.TenableConnectorEnabled.
 * It is false while no sensor runs Tenable commands: sensor v0.8.0 removed the
 * old runner (owner decision D-14), and the two-way Tenable.sc connector is
 * being rebuilt in the sensor (RFC-047). While false, Settings > Integrations >
 * Vulnerability scanners shows only the .nessus import and paused rows; the
 * connect/edit/runner dialogs and the coverage panel are kept in
 * TenableConnectorView. Flip both flags together when the RFC-047 runner ships.
 */
export const TENABLE_CONNECTOR_ENABLED = false
