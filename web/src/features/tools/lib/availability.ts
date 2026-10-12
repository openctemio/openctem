/**
 * Tool availability helpers (api/docs/architecture/tool-availability.md).
 *
 * One reading of GET /api/v1/tools?include=availability for every place that
 * shows or picks a tool: the Tools page, the scan and workflow tool pickers,
 * the sensor detail and the Capabilities page. The data is what the sensors
 * report, so it is advice: the API still checks each scan at trigger and
 * claim time.
 */

import type { PillTone } from '@/features/shared'
import type {
  ToolAvailabilityItem,
  ToolAvailabilitySensor,
  ToolAvailabilityStatus,
} from '@/lib/api/tool-types'

export const TOOL_AVAILABILITY_STATUSES: ToolAvailabilityStatus[] = [
  'ready',
  'outdated',
  'offline_only',
  'no_sensor',
  'disabled',
]

export const TOOL_STATUS_META: Record<
  ToolAvailabilityStatus,
  { label: string; tone: PillTone; description: string }
> = {
  ready: {
    label: 'Ready',
    tone: 'success',
    description: 'At least one online sensor has the tool and may run it.',
  },
  outdated: {
    label: 'Outdated',
    tone: 'warning',
    description:
      'Online sensors have the tool, but every one of them runs a version below the minimum. Scans still run.',
  },
  offline_only: {
    label: 'Offline only',
    tone: 'warning',
    description: 'Sensors have the tool, but none of them is online now.',
  },
  no_sensor: {
    label: 'No sensor',
    tone: 'muted',
    description: 'No sensor of this organization has the tool (or may run it).',
  },
  disabled: {
    label: 'Disabled',
    tone: 'muted',
    description: 'Switched off for this organization.',
  },
}

/** Exclusion reasons, as the API names them. */
export const TOOL_EXCLUSION_LABEL: Record<
  NonNullable<ToolAvailabilitySensor['excluded']>,
  string
> = {
  grant: 'not allowed by its grant',
  local_policy: 'refused by its local policy',
}

/** Whether a scan job for the tool can be dispatched now (ready or outdated). */
export function isRunnable(item: Pick<ToolAvailabilityItem, 'status'>): boolean {
  return item.status === 'ready' || item.status === 'outdated'
}

/** Whether any sensor reports the tool, allowed to run it or not. */
export function onAnySensor(
  item: Pick<ToolAvailabilityItem, 'sensors_total' | 'sensors_excluded'>
): boolean {
  return item.sensors_total + item.sensors_excluded > 0
}

/** The items by tool name. */
export function availabilityByName(
  items: ToolAvailabilityItem[] | undefined
): Map<string, ToolAvailabilityItem> {
  return new Map((items ?? []).map((i) => [i.name, i]))
}

/** The tool's name as people read it. */
export function toolDisplayName(item: Pick<ToolAvailabilityItem, 'name' | 'tool'>): string {
  return item.tool?.display_name || item.name
}

/**
 * Why a scan with this tool cannot run now, in one sentence ("No online
 * sensor has checkov"), or null when it can. inZone: the view was limited to
 * a scan zone's sensors.
 */
export function toolUnavailableReason(
  item: ToolAvailabilityItem | undefined,
  inZone = false
): string | null {
  if (!item || isRunnable(item)) return null
  const where = inZone ? ' in this zone' : ''
  switch (item.status) {
    case 'disabled':
      return item.in_catalog
        ? `${item.name} is switched off for this organization`
        : `${item.name} is not in the tool catalog`
    case 'offline_only':
      return `No online sensor${where} has ${item.name} (${item.sensors_total} offline)`
    default:
      return item.sensors_excluded > 0
        ? `No sensor${where} may run ${item.name}: its grant or local policy does not allow it`
        : `No sensor${where} has ${item.name}`
  }
}

/** "2/3 online"; "none" when no sensor may run the tool. */
export function sensorsLabel(
  item: Pick<ToolAvailabilityItem, 'sensors_online' | 'sensors_total'>
): string {
  if (item.sensors_total === 0) return 'none'
  return `${item.sensors_online}/${item.sensors_total} online`
}

/** "v3.4.2", "v3.3.0 – v3.4.2", or "" when no sensor reports a version. */
export function versionsLabel(
  item: Pick<ToolAvailabilityItem, 'min_reported_version' | 'max_reported_version'>
): string {
  const lo = item.min_reported_version
  const hi = item.max_reported_version
  if (!lo || !hi) return ''
  return lo === hi ? lo : `${lo} – ${hi}`
}

/**
 * The tools one sensor reports that it may not run, with why: what the
 * sensor detail marks next to its tool list.
 */
export function sensorToolExclusions(
  items: ToolAvailabilityItem[] | undefined,
  sensorId: string
): Map<string, { reason: NonNullable<ToolAvailabilitySensor['excluded']>; detail?: string }> {
  const out = new Map<
    string,
    { reason: NonNullable<ToolAvailabilitySensor['excluded']>; detail?: string }
  >()
  for (const item of items ?? []) {
    const s = item.sensors.find((x) => x.id === sensorId)
    if (s?.excluded) out.set(item.name, { reason: s.excluded, detail: s.excluded_detail })
  }
  return out
}
