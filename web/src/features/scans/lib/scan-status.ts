import type { ScanConfig, ScanLastRun } from '@/lib/api/scan-types'
import { toDisplayText } from '@/lib/untrusted-text'

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

/** Readable refusal codes; anything else is shown as sent. */
const REFUSAL_LABELS: Record<string, string> = {
  ALL_TARGETS_EXCLUDED: 'Every target is excluded by scope',
  ALL_TARGETS_UNCONFIRMED: 'No target is authorized for active scanning',
  NO_TARGETS: 'No targets',
  NO_COMPATIBLE_TARGETS: 'No target this scanner can scan',
  NO_SENSOR_AVAILABLE: 'No sensor online',
  SCAN_FREEZE_ACTIVE: 'Freeze window active',
  SCAN_NOT_TRIGGERABLE: 'Scan paused or disabled',
  WILDCARD_TARGET: 'Wildcard pattern given to an active scanner',
  TOOL_DISABLED: 'Scanner disabled',
  TOOL_NOT_FOUND: 'Scanner not available',
  SENSOR_POLICY_REFUSED: "Refused by the sensors' local policy",
  MAX_CONCURRENT_RUNS: 'Too many runs at once',
}

/** One line on why a blocked or failed run ended, for hover text. */
export function lastRunReason(run: ScanLastRun | null): string | undefined {
  if (!run) return undefined
  const label = run.refusal_code ? (REFUSAL_LABELS[run.refusal_code] ?? run.refusal_code) : ''
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
  config: Pick<ScanConfig, 'scan_type' | 'pipeline_name' | 'scanner_name'>
): { label: string; kind: 'workflow' | 'single' } {
  if (config.scan_type === 'workflow') {
    return { label: config.pipeline_name?.trim() || 'Workflow', kind: 'workflow' }
  }
  return { label: config.scanner_name?.trim() || 'Single check', kind: 'single' }
}
