/**
 * The New / Edit scan wizard's form <-> API mapping, in one place so both
 * dialogs send the same thing and the tests exercise the real code.
 *
 * What the form no longer carries, and why: the "Scan type" radio
 * (full/quick/custom/compliance) and the six option checkboxes (port scanning,
 * web app, SSL, brute force, tech detection, API security) plus the intensity
 * slider were written into scanner_config keys that no scanner, sensor or API
 * code reads, and the scanner was hardcoded to nuclei. The wizard now asks for
 * the scanner itself (single) or a real workflow (workflow).
 */

import type {
  CreateScanConfigRequest,
  ScanConfig,
  ScanType as ApiScanType,
  ScheduleType,
  SensorPreference as ApiSensorPreference,
  UpdateScanConfigRequest,
} from '@/lib/api/scan-types'
import { DEFAULT_NEW_SCAN, type NewScanFormData, type ScheduleFrequency } from '../types'
import { parsePastedTargets } from './target-format'
import { enTranslate, type Translate } from './translate'
import { instantToZonedWallTime, viewerTimeZone, zonedWallTimeToInstant } from './zoned-time'
import {
  TENABLE_SC_TOOL,
  readTenableScanConfig,
  tenableScanConfigToApi,
} from '@/features/integrations/lib/tenable-sc'
import { apiTargetOptions, isWildcardTarget, toWildcards } from './dynamic-targets'

/** The scan has no schedule: it runs now, or is saved to start by hand. */
export function onDemand(schedule: NewScanFormData['schedule']): boolean {
  return schedule.runImmediately || !!schedule.saveOnly
}

/** Form schedule frequency -> API schedule type. */
export function frequencyToScheduleType(frequency: ScheduleFrequency | undefined): ScheduleType {
  switch (frequency) {
    case 'once':
    case 'daily':
    case 'weekly':
    case 'monthly':
      return frequency
    default:
      return 'manual'
  }
}

/** API schedule type -> form frequency (unknown types show as weekly). */
export function scheduleTypeToFrequency(scheduleType?: string): ScheduleFrequency {
  switch (scheduleType) {
    case 'once':
    case 'daily':
    case 'weekly':
    case 'monthly':
      return scheduleType
    default:
      return 'weekly'
  }
}

function toApiSensorPreference(preference: string): ApiSensorPreference {
  return preference === 'tenant' || preference === 'platform' ? preference : 'auto'
}

/** First problem with the Basic step, or null. Shared by New and Edit. */
export function basicInfoError(form: NewScanFormData, t: Translate = enTranslate): string | null {
  if (!form.name.trim()) return t('scans.err.name')
  if (form.mode === 'single' && !form.scannerName) return t('scans.err.scanner')
  if (form.mode === 'single' && form.scannerName === TENABLE_SC_TOOL) {
    const config = readTenableScanConfig(form.scannerConfig)
    if (!config.integrationId) return t('scans.err.tenableConnector')
    if (config.policyId <= 0) return t('scans.err.tenablePolicy')
    if (config.repositoryId <= 0) return t('scans.err.tenableRepository')
  }
  if (form.mode === 'workflow' && !form.workflowId) return t('scans.err.workflow')
  return null
}

/** The instant of a once schedule's run, or null when its date/time is incomplete. */
export function onceRunAt(form: NewScanFormData): Date | null {
  const { schedule } = form
  if (!schedule.runAtDate || !schedule.runAtTime) return null
  return zonedWallTimeToInstant(
    { date: schedule.runAtDate, time: schedule.runAtTime },
    schedule.timezone || viewerTimeZone()
  )
}

/**
 * First problem with the Schedule step, or null. A one-off run needs a date
 * and time; a new one must be at least a minute ahead (the API refuses
 * otherwise). An edit may send back a run that has already happened.
 */
export function scheduleError(
  form: NewScanFormData,
  opts: { requireFuture?: boolean; now?: Date } = {},
  t: Translate = enTranslate
): string | null {
  const { schedule } = form
  if (schedule.runImmediately || schedule.saveOnly || schedule.frequency !== 'once') return null
  const at = onceRunAt(form)
  if (!at) return t('scans.err.dateTime')
  const now = opts.now ?? new Date()
  if (opts.requireFuture !== false && at.getTime() < now.getTime() + 60_000) {
    return t('scans.err.future')
  }
  return null
}

function applySchedule(
  form: NewScanFormData,
  request: CreateScanConfigRequest | UpdateScanConfigRequest
) {
  const { schedule } = form
  if (schedule.runImmediately || schedule.saveOnly) return
  // The time is in this zone (the viewer's by default); without it the API
  // read every time as UTC.
  request.timezone = schedule.timezone || viewerTimeZone()
  if (schedule.frequency === 'once') {
    const at = onceRunAt(form)
    if (at) request.run_at = at.toISOString().replace(/\.\d{3}Z$/, 'Z')
    return
  }
  if (schedule.time) request.schedule_time = schedule.time
  if (schedule.frequency === 'weekly' && schedule.dayOfWeek !== undefined) {
    request.schedule_day = schedule.dayOfWeek
  }
  if (schedule.frequency === 'monthly') request.schedule_day = schedule.dayOfMonth ?? 1
}

/** Direct targets a scan takes at most (the API refuses more). */
export const MAX_DIRECT_TARGETS = 1000

function dedupe(all: string[]): string[] {
  return [...new Map(all.map((t) => [t.trim().toLowerCase(), t.trim()])).values()].filter(Boolean)
}

/**
 * Typed targets as sent: valid lines, normalized, without repeats. With a
 * coverage level above `host`, each typed or picked domain becomes
 * `*.domain`, which the API resolves to the domain and its known subdomains
 * at every run (RFC-068); `subdomains_ips` also adds today's addresses.
 */
function typedAndExpanded(form: NewScanFormData): string[] {
  const { targets } = form
  const typed = parsePastedTargets(targets.customTargets).targets
  if (!targets.coverage || targets.coverage === 'host') return dedupe(typed)
  const picked = targets.assetIds.map((id) => targets.assetNames?.[id]).filter(Boolean) as string[]
  const wildcards = toWildcards(picked).filter(isWildcardTarget)
  const all = [...toWildcards(typed), ...wildcards]
  if (targets.coverage === 'subdomains_ips') all.push(...(targets.expandedTargets ?? []))
  return dedupe(all)
}

/**
 * Every direct target the scan probes: picked assets by name, typed and
 * expanded, de-duplicated. What the limit counts and the previews show (the
 * request sends the picked assets as asset_ids; the API names them).
 */
export function directTargets(form: NewScanFormData): string[] {
  const { targets } = form
  const names = targets.assetIds.map((id) => targets.assetNames?.[id]).filter(Boolean) as string[]
  return dedupe([...names, ...typedAndExpanded(form)])
}

/** First problem with the Targets step, or null. Shared by New and Edit. */
export function targetsError(form: NewScanFormData, t: Translate = enTranslate): string | null {
  const { targets } = form
  if (
    targets.assetGroupIds.length === 0 &&
    targets.assetIds.length === 0 &&
    targets.customTargets.length === 0
  ) {
    return t('scans.err.noTarget')
  }
  const invalid = parsePastedTargets(targets.customTargets).invalid.length
  if (invalid > 0) {
    return t(invalid === 1 ? 'scans.err.invalidOne' : 'scans.err.invalidMany', undefined, {
      count: invalid,
    })
  }
  const n = directTargets(form).length
  if (n > MAX_DIRECT_TARGETS) {
    return t('scans.err.tooMany', undefined, {
      max: MAX_DIRECT_TARGETS.toLocaleString(),
      count: n.toLocaleString(),
    })
  }
  return null
}

/** New scan: form -> POST /scans. Combines asset groups, assets and custom targets. */
export function formDataToCreateRequest(form: NewScanFormData): CreateScanConfigRequest {
  const { targets, schedule } = form
  const scanType: ApiScanType = form.mode === 'workflow' ? 'workflow' : 'single'

  const request: CreateScanConfigRequest = {
    name: form.name.trim(),
    intensity: form.intensity,
    scan_type: scanType,
    schedule_type: onDemand(schedule) ? 'manual' : frequencyToScheduleType(schedule.frequency),
    sensor_preference: toApiSensorPreference(form.sensorPreference),
    targets_per_job: form.maxConcurrent || 10,
    timeout_seconds: form.timeoutSeconds,
    max_retries: form.maxRetries,
    retry_backoff_seconds: form.retryBackoffSeconds,
  }
  if (form.profileId) request.profile_id = form.profileId
  if (form.scanZoneId) request.scan_zone_id = form.scanZoneId
  const targetOptions = apiTargetOptions(targets.targetOptions)
  if (targetOptions) request.target_options = targetOptions

  if (targets.assetGroupIds.length > 0) {
    request.asset_group_ids = targets.assetGroupIds
    // asset_group_id for older API versions
    request.asset_group_id = targets.assetGroupIds[0]
  }
  // Never cut silently: targetsError stops the wizard above the limit, and
  // the API refuses more than MAX_DIRECT_TARGETS with its own message.
  // Picked assets go by id: the API names them and checks the creator may
  // scan them (an id is not a name the browser could get wrong).
  if (targets.assetIds.length > 0) request.asset_ids = [...targets.assetIds]
  const typed = typedAndExpanded(form)
  if (typed.length > 0) request.targets = typed

  if (form.mode === 'workflow' && form.workflowId) request.scan_workflow_id = form.workflowId
  if (form.mode === 'single') request.scanner_name = form.scannerName
  if (form.mode === 'single' && form.scannerName === TENABLE_SC_TOOL) {
    request.scanner_config = tenableScanConfigToApi(readTenableScanConfig(form.scannerConfig))
  }

  applySchedule(form, request)
  return request
}

/** A configuration's schedule as the wizard shows it (in the scan's zone). */
function scheduleFromConfig(config: ScanConfig): NewScanFormData['schedule'] {
  const timezone = config.schedule_timezone || undefined
  const frequency = scheduleTypeToFrequency(config.schedule_type)
  const runAt =
    config.schedule_type === 'once' && config.schedule_run_at
      ? instantToZonedWallTime(config.schedule_run_at, timezone ?? 'UTC')
      : null
  return {
    runImmediately: config.schedule_type === 'manual',
    frequency,
    dayOfWeek: frequency === 'weekly' ? config.schedule_day : DEFAULT_NEW_SCAN.schedule.dayOfWeek,
    dayOfMonth: frequency === 'monthly' ? config.schedule_day : undefined,
    time: config.schedule_time?.slice(0, 5) ?? DEFAULT_NEW_SCAN.schedule.time,
    runAtDate: runAt?.date,
    runAtTime: runAt?.time,
    timezone,
  }
}

/** Edit: an existing configuration -> wizard form data. */
export function scanConfigToFormData(config: ScanConfig): NewScanFormData {
  return {
    ...DEFAULT_NEW_SCAN,
    name: config.name,
    intensity: config.intensity ?? DEFAULT_NEW_SCAN.intensity,
    mode: config.scan_type === 'workflow' ? 'workflow' : 'single',
    scannerName: config.scanner_name ?? '',
    scannerConfig: config.scanner_config ? { ...config.scanner_config } : undefined,
    workflowId: config.scan_workflow_id,
    sensorPreference: config.sensor_preference || 'auto',
    targets: {
      type: 'asset_groups',
      assetGroupIds:
        config.asset_group_ids ?? (config.asset_group_id ? [config.asset_group_id] : []),
      assetIds: [],
      assetNames: {},
      customTargets: config.targets ?? [],
      targetOptions: config.target_options,
    },
    maxConcurrent: config.targets_per_job || 10,
    timeoutSeconds: config.timeout_seconds || 3600,
    maxRetries: config.max_retries ?? 0,
    retryBackoffSeconds: config.retry_backoff_seconds || 60,
    schedule: scheduleFromConfig(config),
    scanZoneId: config.scan_zone_id ?? null,
  }
}

/**
 * Edit: form -> PUT /scans/{id}.
 *
 * The scanner sent is the one the form holds, which starts as the
 * configuration's own: saving no longer resets it to nuclei. scanner_config
 * is sent back as stored (the API replaces the whole map, and restores values
 * it showed masked), never with wizard-only keys added.
 */
export function formDataToUpdateRequest(
  form: NewScanFormData,
  config: ScanConfig,
  opts: { canSetZone: boolean }
): UpdateScanConfigRequest {
  const { schedule } = form
  const request: UpdateScanConfigRequest = {
    name: form.name.trim(),
    intensity: form.intensity,
    description: config.description || undefined,
    scanner_config: { ...(config.scanner_config ?? {}) },
    targets_per_job: form.maxConcurrent || 10,
    timeout_seconds: form.timeoutSeconds,
    max_retries: form.maxRetries,
    retry_backoff_seconds: form.retryBackoffSeconds,
    schedule_type: onDemand(schedule) ? 'manual' : frequencyToScheduleType(schedule.frequency),
    sensor_preference: toApiSensorPreference(form.sensorPreference),
  }
  // Only someone who can see the zones may change the zone: otherwise an
  // empty picker would reset a restricted scan to Automatic.
  if (opts.canSetZone) request.scan_zone_id = form.scanZoneId ?? ''
  // Sent whole: {} resets every option to its default (RFC-068).
  request.target_options = apiTargetOptions(form.targets.targetOptions) ?? {}

  if (form.mode === 'workflow' && form.workflowId) request.scan_workflow_id = form.workflowId
  if (form.mode === 'single' && form.scannerName) request.scanner_name = form.scannerName
  if (form.mode === 'single' && form.scannerName === TENABLE_SC_TOOL) {
    request.scanner_config = tenableScanConfigToApi(
      readTenableScanConfig(form.scannerConfig),
      config.scanner_config
    )
  }

  applySchedule(form, request)
  return request
}
