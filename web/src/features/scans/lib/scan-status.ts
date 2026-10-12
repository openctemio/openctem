import type { ScanConfig, ScanLastRun } from '@/lib/api/scan-types'
import { toDisplayText } from '@/lib/untrusted-text'
import { enTranslate, type Translate } from './translate'

/**
 * What a scan list row says about a scan: its latest run (the real run
 * state), whether it has a schedule to switch on or off, and what it runs.
 * A scan is a configuration; a run is one execution of it (RFC-046). The
 * configuration's enabled flag only gates its schedule, so it is never shown
 * as if it were a run state.
 */

/** A scan has a schedule to switch on or off (not manual-only). */
export function hasSchedule(config: Pick<ScanConfig, 'schedule_type'>): boolean {
  return config.schedule_type !== 'manual'
}

/** Whether the schedule is on: the scan is enabled and not paused. */
export function scheduleOn(config: Pick<ScanConfig, 'status'>): boolean {
  return config.status === 'active'
}

/**
 * The scan's latest run. Older API builds sent only last_run_id/at/status;
 * those are used when last_run is absent. Null when the scan never ran.
 */
export function lastRunOf(
  config: Pick<ScanConfig, 'last_run' | 'last_run_id' | 'last_run_at' | 'last_run_status'>
): ScanLastRun | null {
  if (config.last_run) return config.last_run
  if (config.last_run_id && config.last_run_at && config.last_run_status) {
    return {
      id: config.last_run_id,
      status: config.last_run_status,
      created_at: config.last_run_at,
    }
  }
  return null
}

/** Refusal codes with a translated label; any other code is shown as sent. */
const REFUSAL_CODES = new Set([
  'ALL_TARGETS_EXCLUDED',
  'ALL_TARGETS_UNCONFIRMED',
  'NO_TARGETS',
  'NO_COMPATIBLE_TARGETS',
  'NO_SENSOR_AVAILABLE',
  'SCAN_WINDOW_NEVER_OPENS',
  'SCAN_NOT_TRIGGERABLE',
  'WILDCARD_TARGET',
  'TARGET_SELECTOR_UNAVAILABLE',
  'TOOL_DISABLED',
  'TOOL_NOT_FOUND',
  'SENSOR_POLICY_REFUSED',
  'MAX_CONCURRENT_RUNS',
])

/** One line on why a blocked or failed run ended, for hover text. */
export function lastRunReason(
  run: ScanLastRun | null,
  t: Translate = enTranslate
): string | undefined {
  if (!run) return undefined
  const label = run.refusal_code
    ? REFUSAL_CODES.has(run.refusal_code)
      ? t(`scans.refusal.${run.refusal_code}`)
      : run.refusal_code
    : ''
  // The message can carry sensor or tool text: control and direction
  // characters are shown as escapes, never applied.
  const message = toDisplayText(run.error_message?.trim() ?? '')
  if (label && message) return `${label}: ${message}`
  return label || message || undefined
}

/**
 * What the scan runs, for the Type column: the workflow's name, or the
 * scanner of a single check. `kind` says which.
 */
export function scanTypeLabel(
  config: Pick<ScanConfig, 'scan_type' | 'scan_workflow_name' | 'scanner_name'>,
  t: Translate = enTranslate
): { label: string; kind: 'workflow' | 'single' } {
  if (config.scan_type === 'workflow') {
    return {
      label: config.scan_workflow_name?.trim() || t('scans.scanType.workflow'),
      kind: 'workflow',
    }
  }
  return { label: config.scanner_name?.trim() || t('scans.scanType.single'), kind: 'single' }
}
