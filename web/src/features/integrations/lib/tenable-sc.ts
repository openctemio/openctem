/**
 * Tenable.sc sensor connector (api docs/rfcs/RFC-047): reading the state the
 * API keeps on the integration (metadata.tenable_sync) and building the
 * connector's config. Pure functions, shared by the connector page, the
 * coverage panel and the scan wizard.
 *
 * The platform never holds Tenable credentials or the Tenable URL: nothing
 * here reads or writes them.
 */

import type { Integration } from '@/features/integrations/types/integration.types'
import type { Sensor } from '@/lib/api/sensor-types'

/** The connector's tool name (sensor tool, scan scanner_name). */
export const TENABLE_SC_TOOL = 'tenable_sc'

export interface CatalogItem {
  id: number
  name: string
}

/** What the sensor reported it allows (filtered to its owner's allow-lists). */
export interface TenableCatalog {
  repositories: CatalogItem[]
  scanRepositories: CatalogItem[]
  policies: CatalogItem[]
  scanZones: CatalogItem[]
}

export interface TenableSyncState {
  openCommandId?: string
  openMode?: string
  lastSuccessfulSync?: string
  lastFullSync?: string
  lastOutcome?: 'completed' | 'failed' | string
  tenableVersion?: string
  licensedIPs: number
  activeIPs: number
  hosts: number
  open: number
  mitigated: number
  plugins: number
  catalog: TenableCatalog | null
  coverageCommandId?: string
  lastCoverageOutcome?: string
}

function obj(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : undefined
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v !== '' ? v : undefined
}

function num(v: unknown): number {
  const n = typeof v === 'number' ? v : typeof v === 'string' ? Number(v) : NaN
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0
}

function items(v: unknown): CatalogItem[] {
  if (!Array.isArray(v)) return []
  const out: CatalogItem[] = []
  for (const raw of v) {
    const o = obj(raw)
    const id = num(o?.id)
    if (!o || id <= 0) continue
    out.push({ id, name: str(o.name) ?? `#${id}` })
  }
  return out
}

/** The connector's sync state, from the integration's metadata (untrusted shapes are tolerated). */
export function readTenableSync(integration: Integration | undefined): TenableSyncState {
  const s = obj(obj(integration?.metadata)?.tenable_sync) ?? {}
  const c = obj(s.catalog)
  return {
    openCommandId: str(s.open_command_id),
    openMode: str(s.open_mode),
    lastSuccessfulSync: str(s.last_successful_sync),
    lastFullSync: str(s.last_full_sync),
    lastOutcome: str(s.last_outcome),
    tenableVersion: str(s.tenable_version),
    licensedIPs: num(s.licensed_ips),
    activeIPs: num(s.active_ips),
    hosts: num(s.hosts),
    open: num(s.open),
    mitigated: num(s.mitigated),
    plugins: num(s.plugins),
    catalog: c
      ? {
          repositories: items(c.repositories),
          scanRepositories: items(c.scan_repositories),
          policies: items(c.policies),
          scanZones: items(c.scan_zones),
        }
      : null,
    coverageCommandId: str(s.coverage_command_id),
    lastCoverageOutcome: str(s.last_coverage_outcome),
  }
}

function config(integration: Integration | undefined): Record<string, unknown> {
  return obj(integration?.config) ?? {}
}

/** A Tenable integration that is the Tenable.sc sensor connector. */
export function isTenableSCConnector(integration: Integration | undefined): boolean {
  if (!integration || integration.provider !== 'tenable') return false
  const c = config(integration)
  return c.engine === 'tenable_sc' && (c.execution_mode ?? 'sensor') === 'sensor'
}

export interface ConnectorSettings {
  sensorId: string
  instance: string
  minSeverity: number
  fullSyncDays: number
  coverageEnabled: boolean
  coveragePolicyId: number
  coverageRepositoryId: number
  batchSize: number
  licenseCap: number
  safetyMargin: number
}

export const DEFAULT_CONNECTOR_SETTINGS: ConnectorSettings = {
  sensorId: '',
  instance: 'default',
  minSeverity: 1,
  fullSyncDays: 7,
  coverageEnabled: false,
  coveragePolicyId: 0,
  coverageRepositoryId: 0,
  batchSize: 0,
  licenseCap: 0,
  safetyMargin: 0,
}

/** The connector settings stored in the integration's config. */
export function readConnectorSettings(integration: Integration | undefined): ConnectorSettings {
  const c = config(integration)
  const n = (k: string, d = 0) => (c[k] === undefined || c[k] === null ? d : num(c[k]))
  return {
    sensorId: str(c.sensor_id) ?? '',
    instance: str(c.instance) ?? 'default',
    minSeverity: c.min_severity === 0 ? 0 : n('min_severity', 1),
    fullSyncDays: n('full_sync_days', 7),
    coverageEnabled: c.coverage_enabled === true || c.coverage_enabled === 'true',
    coveragePolicyId: n('coverage_policy_id'),
    coverageRepositoryId: n('coverage_repository_id'),
    batchSize: n('batch_size'),
    licenseCap: n('license_cap'),
    safetyMargin: n('safety_margin'),
  }
}

export const INSTANCE_NAME_RE = /^[a-z0-9][a-z0-9_.-]{0,62}$/

/** First problem with the settings, or null (the API checks the same rules). */
export function connectorSettingsError(s: ConnectorSettings): string | null {
  if (!s.sensorId) return 'Choose the sensor that runs the Tenable.sc connector'
  if (!INSTANCE_NAME_RE.test(s.instance))
    return "Instance: 1-63 lowercase letters, digits, '.', '_' or '-'"
  if (s.minSeverity < 0 || s.minSeverity > 4) return 'Minimum severity must be 0 to 4'
  if (s.fullSyncDays < 1 || s.fullSyncDays > 90) return 'Full sync every 1 to 90 days'
  if (s.coverageEnabled && (s.coveragePolicyId <= 0 || s.coverageRepositoryId <= 0))
    return 'Coverage needs a scan policy and a scan repository'
  return null
}

/**
 * The integration config for the settings: always engine tenable_sc in sensor
 * mode, so the API never asks for credentials. Keys not managed here (set by
 * the API or an older UI) are kept.
 */
export function connectorConfig(
  s: ConnectorSettings,
  existing?: Record<string, unknown>
): Record<string, unknown> {
  const out: Record<string, unknown> = {
    ...(existing ?? {}),
    engine: 'tenable_sc',
    execution_mode: 'sensor',
    sensor_id: s.sensorId,
    instance: s.instance,
    min_severity: s.minSeverity,
    full_sync_days: s.fullSyncDays,
    coverage_enabled: s.coverageEnabled,
  }
  const optional: Array<[string, number]> = [
    ['coverage_policy_id', s.coveragePolicyId],
    ['coverage_repository_id', s.coverageRepositoryId],
    ['batch_size', s.batchSize],
    ['license_cap', s.licenseCap],
    ['safety_margin', s.safetyMargin],
  ]
  for (const [k, v] of optional) {
    if (v > 0) out[k] = v
    else delete out[k]
  }
  return out
}

export interface ConnectorSensorOption {
  sensor: Sensor
  /** The sensor reports the tenable_sc tool installed (it can run the connector now). */
  runsConnector: boolean
}

/** The tenant's own active sensors, those that run the connector first. Platform sensors never run a tenant's connector. */
export function connectorSensorOptions(sensors: Sensor[] | undefined): ConnectorSensorOption[] {
  return (sensors ?? [])
    .filter((s) => !s.is_platform_sensor && s.status === 'active')
    .map((sensor) => ({
      sensor,
      runsConnector:
        sensor.reported?.tools?.some((t) => t.name === TENABLE_SC_TOOL && t.installed) ?? false,
    }))
    .sort(
      (a, b) =>
        Number(b.runsConnector) - Number(a.runsConnector) ||
        a.sensor.name.localeCompare(b.sensor.name)
    )
}

export interface CoverageNumbers {
  enabled: boolean
  /** null until a sync reported Tenable.sc's license numbers. */
  licensed: number | null
  active: number | null
  /** The effective limit (the configured cap when lower than the license). */
  limit: number | null
  safetyMargin: number
  /** Addresses the next batch may use; null when unknown. */
  headroom: number | null
  batchOpen: boolean
  lastBatchOutcome?: string
}

/** The coverage panel's numbers, computed the way the API sizes a batch. */
export function coverageNumbers(integration: Integration | undefined): CoverageNumbers {
  const s = readConnectorSettings(integration)
  const sync = readTenableSync(integration)
  const licensed = sync.licensedIPs > 0 ? sync.licensedIPs : null
  const limit =
    licensed === null ? null : s.licenseCap > 0 ? Math.min(licensed, s.licenseCap) : licensed
  const active = licensed === null ? null : sync.activeIPs
  const headroom =
    limit === null || active === null ? null : Math.max(0, limit - active - s.safetyMargin)
  return {
    enabled: s.coverageEnabled,
    licensed,
    active,
    limit,
    safetyMargin: s.safetyMargin,
    headroom,
    batchOpen: Boolean(sync.coverageCommandId),
    lastBatchOutcome: sync.lastCoverageOutcome,
  }
}

/** A tenable_sc scan's scanner_config. */
export interface TenableScanConfig {
  integrationId: string
  policyId: number
  repositoryId: number
  zoneId: number
}

export function readTenableScanConfig(cfg: Record<string, unknown> | undefined): TenableScanConfig {
  const c = cfg ?? {}
  return {
    integrationId: str(c.integration_id) ?? '',
    policyId: num(c.policy_id),
    repositoryId: num(c.repository_id),
    zoneId: num(c.zone_id),
  }
}

export function tenableScanConfigError(c: TenableScanConfig): string | null {
  if (!c.integrationId) return 'Choose the Tenable.sc connector'
  if (c.policyId <= 0) return 'Choose a Tenable.sc scan policy'
  if (c.repositoryId <= 0) return 'Choose a Tenable.sc repository'
  return null
}

export function tenableScanConfigToApi(
  c: TenableScanConfig,
  existing?: Record<string, unknown>
): Record<string, unknown> {
  const out: Record<string, unknown> = {
    ...(existing ?? {}),
    integration_id: c.integrationId,
    policy_id: c.policyId,
    repository_id: c.repositoryId,
  }
  if (c.zoneId > 0) out.zone_id = c.zoneId
  else delete out.zone_id
  return out
}
