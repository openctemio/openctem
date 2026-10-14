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
  /** When the next coverage batch may go, and why it waits (API words). */
  nextBatchAt?: string
  coverageWait?: string
  /** Set when a recycle rotation stalled; an administrator resumes it. */
  rotationStalled?: string
  /** Addresses the last batch added to the license count. */
  lastBatchAdded: number
  /** Coverage cycle: number, progress and ETA (0 / undefined before the first batch). */
  cycle: number
  cycleStartedAt?: string
  cycleAssessed: number
  cycleEligible: number
  cycleEta?: string
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
    nextBatchAt: str(s.next_batch_at),
    coverageWait: str(s.coverage_wait),
    rotationStalled: str(s.rotation_stalled),
    lastBatchAdded: num(s.last_batch_added),
    cycle: num(s.cycle),
    cycleStartedAt: str(s.cycle_started_at),
    cycleAssessed: num(s.cycle_assessed),
    cycleEligible: num(s.cycle_eligible),
    cycleEta: str(s.cycle_eta),
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

/**
 * How license capacity comes back between coverage batches (api research/143
 * §4): off (cover what the license holds), aging (Tenable.sc's nightly
 * cleanup frees it) or recycle (the connector recreates its rotation
 * repository). Anything but off needs the administrator's acknowledgement.
 */
export type CoverageRotation = 'off' | 'aging' | 'recycle'

export const COVERAGE_ROTATIONS: CoverageRotation[] = ['off', 'aging', 'recycle']

/** The aging wait the API uses when none is set, and its bounds. */
export const DEFAULT_ROTATION_WAIT_HOURS = 12
export const MIN_ROTATION_WAIT_HOURS = 1
export const MAX_ROTATION_WAIT_HOURS = 72

function rotationOf(v: unknown): CoverageRotation {
  const r = typeof v === 'string' ? v.trim().toLowerCase() : ''
  return r === 'aging' || r === 'recycle' ? r : 'off'
}

export interface ConnectorSettings {
  sensorId: string
  instance: string
  minSeverity: number
  fullSyncDays: number
  /** The public names and addresses it syncs get their exact scope entries. */
  assetsInScope: boolean
  coverageEnabled: boolean
  coveragePolicyId: number
  coverageRepositoryId: number
  batchSize: number
  licenseCap: number
  safetyMargin: number
  rotation: CoverageRotation
  rotationAcknowledged: boolean
  rotationWaitHours: number
}

export const DEFAULT_CONNECTOR_SETTINGS: ConnectorSettings = {
  sensorId: '',
  instance: 'default',
  minSeverity: 1,
  fullSyncDays: 7,
  assetsInScope: true,
  coverageEnabled: false,
  coveragePolicyId: 0,
  coverageRepositoryId: 0,
  batchSize: 0,
  licenseCap: 0,
  safetyMargin: 0,
  rotation: 'off',
  rotationAcknowledged: false,
  rotationWaitHours: DEFAULT_ROTATION_WAIT_HOURS,
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
    assetsInScope: c.assets_in_scope !== false,
    coverageEnabled: c.coverage_enabled === true || c.coverage_enabled === 'true',
    coveragePolicyId: n('coverage_policy_id'),
    coverageRepositoryId: n('coverage_repository_id'),
    batchSize: n('batch_size'),
    licenseCap: n('license_cap'),
    safetyMargin: n('safety_margin'),
    rotation: rotationOf(c.coverage_rotation),
    rotationAcknowledged:
      c.coverage_rotation_acknowledged === true || c.coverage_rotation_acknowledged === 'true',
    rotationWaitHours: n('coverage_rotation_wait_hours', DEFAULT_ROTATION_WAIT_HOURS),
  }
}

export const INSTANCE_NAME_RE = /^[a-z0-9][a-z0-9_.-]{0,62}$/

/** A user-facing message: the caller translates it with t(key, fallback). */
export interface TenableMessage {
  key: string
  fallback: string
}

const msg = (key: string, fallback: string): TenableMessage => ({
  key: `tenableSc.error.${key}`,
  fallback,
})

/** First problem with the settings, or null (the API checks the same rules). */
export function connectorSettingsError(s: ConnectorSettings): TenableMessage | null {
  if (!s.sensorId)
    return msg('chooseSensor', 'Choose the sensor that runs the Tenable.sc connector')
  if (!INSTANCE_NAME_RE.test(s.instance))
    return msg('instance', "Instance: 1-63 lowercase letters, digits, '.', '_' or '-'")
  if (s.minSeverity < 0 || s.minSeverity > 4)
    return msg('minSeverity', 'Minimum severity must be 0 to 4')
  if (s.fullSyncDays < 1 || s.fullSyncDays > 90)
    return msg('fullSyncDays', 'Full sync every 1 to 90 days')
  if (s.coverageEnabled && (s.coveragePolicyId <= 0 || s.coverageRepositoryId <= 0))
    return msg('coverageNeedsPolicy', 'Coverage needs a scan policy and a scan repository')
  if (s.rotation !== 'off' && !s.rotationAcknowledged)
    return msg(
      'rotationNeedsAck',
      "License rotation needs the confirmation that this organization's Tenable license terms allow it"
    )
  if (
    !Number.isInteger(s.rotationWaitHours) ||
    s.rotationWaitHours < MIN_ROTATION_WAIT_HOURS ||
    s.rotationWaitHours > MAX_ROTATION_WAIT_HOURS
  )
    return msg('rotationWaitHours', 'Wait after a batch: 1 to 72 hours')
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
    assets_in_scope: s.assetsInScope,
    coverage_enabled: s.coverageEnabled,
    coverage_rotation: s.rotation,
    // The acknowledgement is kept only while rotation is on: turning it off
    // and on again asks for the confirmation again.
    coverage_rotation_acknowledged: s.rotation !== 'off' && s.rotationAcknowledged,
    coverage_rotation_wait_hours: s.rotationWaitHours,
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

/** The tenant's own active sensors (the API lists no other), those that run the connector first. */
export function connectorSensorOptions(sensors: Sensor[] | undefined): ConnectorSensorOption[] {
  return (sensors ?? [])
    .filter((s) => s.status === 'active')
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
  rotation: CoverageRotation
}

/** The coverage panel's numbers, computed the way the API sizes a batch. */
export function coverageNumbers(integration: Integration | undefined): CoverageNumbers {
  const s = readConnectorSettings(integration)
  const sync = readTenableSync(integration)
  const licensed = sync.licensedIPs > 0 ? sync.licensedIPs : null
  const limit =
    licensed === null ? null : s.licenseCap > 0 ? Math.min(licensed, s.licenseCap) : licensed
  const active = licensed === null ? null : sync.activeIPs
  // With rotation the last batch's addresses leave the count before the
  // next batch (aging cleanup or recycling), as the API sizes it.
  const base =
    active === null
      ? null
      : s.rotation === 'off'
        ? active
        : Math.max(0, active - sync.lastBatchAdded)
  const headroom =
    limit === null || base === null ? null : Math.max(0, limit - base - s.safetyMargin)
  return {
    enabled: s.coverageEnabled,
    licensed,
    active,
    limit,
    safetyMargin: s.safetyMargin,
    headroom,
    batchOpen: Boolean(sync.coverageCommandId),
    lastBatchOutcome: sync.lastCoverageOutcome,
    rotation: s.rotation,
  }
}

export interface RotationProgress {
  rotation: CoverageRotation
  /** 0 before the first batch. */
  cycle: number
  assessed: number
  eligible: number
  /** 0-100, null while nothing is eligible yet. */
  percent: number | null
  eta?: string
  nextBatchAt?: string
  /** Why the next batch waits (the API's words), only while it does. */
  waitReason?: string
  stalled?: string
}

/** The coverage cycle of a connector, for the coverage panel. */
export function rotationProgress(
  integration: Integration | undefined,
  now: Date = new Date()
): RotationProgress {
  const s = readConnectorSettings(integration)
  const sync = readTenableSync(integration)
  const eligible = sync.cycleEligible
  const assessed = Math.min(sync.cycleAssessed, eligible || sync.cycleAssessed)
  const waiting =
    sync.nextBatchAt !== undefined && new Date(sync.nextBatchAt).getTime() > now.getTime()
  return {
    rotation: s.rotation,
    cycle: sync.cycle,
    assessed,
    eligible,
    percent: eligible > 0 ? Math.min(100, Math.round((assessed / eligible) * 100)) : null,
    eta: sync.cycleEta,
    nextBatchAt: waiting ? sync.nextBatchAt : undefined,
    waitReason: waiting ? sync.coverageWait : undefined,
    stalled: sync.rotationStalled,
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

/** The connector integrations among a tenant's integrations. */
export function tenableSCConnectors(integrations: Integration[] | undefined): Integration[] {
  return (integrations ?? []).filter(isTenableSCConnector)
}

/** Asset types a connector scan targets (scanned by their address or host name). */
export const TENABLE_SCANNABLE_ASSET_TYPES = ['ip_address', 'host'] as const

export function isTenableScannableAssetType(type: string | undefined): boolean {
  return (TENABLE_SCANNABLE_ASSET_TYPES as readonly string[]).includes(type ?? '')
}

/** A finding the connector reported (its tool or source is tenable_sc). */
export function isTenableSCFinding(f: { toolName?: string; source?: string } | undefined): boolean {
  return f?.toolName === TENABLE_SC_TOOL || f?.source === TENABLE_SC_TOOL
}

export function tenableScanConfigError(c: TenableScanConfig): TenableMessage | null {
  if (!c.integrationId) return msg('chooseConnector', 'Choose the Tenable.sc connector')
  if (c.policyId <= 0) return msg('choosePolicy', 'Choose a Tenable.sc scan policy')
  if (c.repositoryId <= 0) return msg('chooseRepository', 'Choose a Tenable.sc repository')
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
