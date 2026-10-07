/**
 * The New / Edit scan wizard's form <-> API mapping, in one place so both
 * dialogs send the same thing and the tests exercise the real code.
 *
 * What the form no longer carries, and why: the "Scan type" radio
 * (full/quick/custom/compliance) and the six option checkboxes (port scanning,
 * web app, SSL, brute force, tech detection, API security) plus the intensity
 * slider were written into scanner_config keys that no scanner, sensor or API
 * code reads, and the scanner was hardcoded to nuclei. The wizard now asks for
 * the scanner itself (single) or a real pipeline (workflow).
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
import {
  TENABLE_SC_TOOL,
  readTenableScanConfig,
  tenableScanConfigError,
  tenableScanConfigToApi,
} from '@/features/integrations/lib/tenable-sc'

/** Form schedule frequency -> API schedule type ("once" is manual). */
export function frequencyToScheduleType(frequency: ScheduleFrequency | undefined): ScheduleType {
  switch (frequency) {
    case 'daily':
    case 'weekly':
    case 'monthly':
      return frequency
    default:
      return 'manual'
  }
}

/** API schedule type -> form frequency (manual and unknown are "once"). */
export function scheduleTypeToFrequency(scheduleType?: string): ScheduleFrequency {
  switch (scheduleType) {
    case 'daily':
    case 'weekly':
    case 'monthly':
      return scheduleType
    default:
      return 'once'
  }
}

function toApiSensorPreference(preference: string): ApiSensorPreference {
  return preference === 'tenant' || preference === 'platform' ? preference : 'auto'
}

/** First problem with the Basic step, or null. Shared by New and Edit. */
export function basicInfoError(form: NewScanFormData): string | null {
  if (!form.name.trim()) return 'Please enter a scan name'
  if (form.mode === 'single' && !form.scannerName) return 'Please choose a scanner'
  if (form.mode === 'single' && form.scannerName === TENABLE_SC_TOOL) {
    const problem = tenableScanConfigError(readTenableScanConfig(form.scannerConfig))
    if (problem) return problem
  }
  if (form.mode === 'workflow' && !form.workflowId) return 'Please select a workflow'
  return null
}

function applySchedule(
  form: NewScanFormData,
  request: CreateScanConfigRequest | UpdateScanConfigRequest
) {
  const { schedule } = form
  if (schedule.runImmediately || schedule.frequency === 'once') return
  if (schedule.time) request.schedule_time = schedule.time
  if (schedule.frequency === 'weekly' && schedule.dayOfWeek !== undefined) {
    request.schedule_day = schedule.dayOfWeek
  }
  if (schedule.frequency === 'monthly') request.schedule_day = 1 // first of the month
}

/** New scan: form -> POST /scans. Combines asset groups, assets and custom targets. */
export function formDataToCreateRequest(form: NewScanFormData): CreateScanConfigRequest {
  const { targets, schedule } = form
  const scanType: ApiScanType = form.mode === 'workflow' ? 'workflow' : 'single'

  const request: CreateScanConfigRequest = {
    name: form.name.trim(),
    scan_type: scanType,
    schedule_type: schedule.runImmediately ? 'manual' : frequencyToScheduleType(schedule.frequency),
    sensor_preference: toApiSensorPreference(form.sensorPreference),
    targets_per_job: form.maxConcurrent || 10,
    timeout_seconds: form.timeoutSeconds,
    max_retries: form.maxRetries,
    retry_backoff_seconds: form.retryBackoffSeconds,
  }
  if (form.profileId) request.profile_id = form.profileId
  if (form.scanZoneId) request.scan_zone_id = form.scanZoneId

  if (targets.assetGroupIds.length > 0) {
    request.asset_group_ids = targets.assetGroupIds
    // asset_group_id for older API versions
    request.asset_group_id = targets.assetGroupIds[0]
  }
  const all: string[] = []
  for (const id of targets.assetIds) {
    const name = targets.assetNames?.[id]
    if (name) all.push(name)
  }
  all.push(...targets.customTargets)
  if (all.length > 0) request.targets = all

  if (form.mode === 'workflow' && form.workflowId) request.scan_workflow_id = form.workflowId
  if (form.mode === 'single') request.scanner_name = form.scannerName
  if (form.mode === 'single' && form.scannerName === TENABLE_SC_TOOL) {
    request.scanner_config = tenableScanConfigToApi(readTenableScanConfig(form.scannerConfig))
  }

  applySchedule(form, request)
  return request
}

/** Edit: an existing configuration -> wizard form data. */
export function scanConfigToFormData(config: ScanConfig): NewScanFormData {
  return {
    ...DEFAULT_NEW_SCAN,
    name: config.name,
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
    },
    maxConcurrent: config.targets_per_job || 10,
    timeoutSeconds: config.timeout_seconds || 3600,
    maxRetries: config.max_retries ?? 0,
    retryBackoffSeconds: config.retry_backoff_seconds || 60,
    schedule: {
      runImmediately: config.schedule_type === 'manual',
      frequency: scheduleTypeToFrequency(config.schedule_type),
      dayOfWeek: config.schedule_day,
      time: config.schedule_time,
    },
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
    description: config.description || undefined,
    scanner_config: { ...(config.scanner_config ?? {}) },
    targets_per_job: form.maxConcurrent || 10,
    timeout_seconds: form.timeoutSeconds,
    max_retries: form.maxRetries,
    retry_backoff_seconds: form.retryBackoffSeconds,
    schedule_type: schedule.runImmediately ? 'manual' : frequencyToScheduleType(schedule.frequency),
    sensor_preference: toApiSensorPreference(form.sensorPreference),
  }
  // Only someone who can see the zones may change the zone: otherwise an
  // empty picker would reset a restricted scan to Automatic.
  if (opts.canSetZone) request.scan_zone_id = form.scanZoneId ?? ''

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
