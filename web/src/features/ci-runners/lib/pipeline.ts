/**
 * CI pipelines in the fleet (api RFC-051 §10): one workflow file of one
 * repository, shown on the Sensors page as a sensor in runner mode. Its
 * status is computed by the API from its runs against its own cadence; a
 * pipeline is never "offline".
 */

import type { PillTone } from '@/features/shared/components/tone-pill'
import type { CIPipelineStatus, FleetMode } from '../types'

export interface PipelineStatusMeta {
  label: string
  tone: PillTone
  description: string
}

/**
 * Severity order (the API's badge order): failing > degraded > stale >
 * running/fresh; revoked, archived and never-run are inactive. No status is
 * red except a failing gate: silence is stale (amber), never offline.
 */
export const PIPELINE_STATUS_META: Record<CIPipelineStatus, PipelineStatusMeta> = {
  failing: {
    label: 'Failing',
    tone: 'destructive',
    description: 'The last run on the default branch failed the CI gate.',
  },
  degraded: {
    label: 'Degraded',
    tone: 'warning',
    description:
      'Scanners failed in the last run, or the runner is older than the minimum supported version.',
  },
  stale: {
    label: 'Stale',
    tone: 'warning',
    description:
      'No run within its expected cadence: two missed scheduled cycles, or three times its usual interval.',
  },
  running: { label: 'Running', tone: 'info', description: 'A run is in progress.' },
  fresh: { label: 'Fresh', tone: 'success', description: 'It ran within its expected cadence.' },
  never: {
    label: 'Never ran',
    tone: 'muted',
    description: 'Registered, but no run of its own yet (only fork runs, or backfilled).',
  },
  archived: {
    label: 'Archived',
    tone: 'muted',
    description: 'Idle for 90 days. Nothing is deleted; the next run brings it back.',
  },
  revoked: {
    label: 'Revoked',
    tone: 'muted',
    description:
      'Its trust configuration was disabled, deleted or changed. The next admitted run brings it back.',
  },
}

export const PIPELINE_STATUSES = Object.keys(PIPELINE_STATUS_META) as CIPipelineStatus[]

/** Hidden unless "Show inactive" is on (hidden is never deleted). */
export const INACTIVE_PIPELINE_STATUSES: CIPipelineStatus[] = ['archived', 'revoked', 'never']

export function isPipelineStatus(s: string | undefined): s is CIPipelineStatus {
  return !!s && s in PIPELINE_STATUS_META
}

export function pipelineStatusMeta(s: string | undefined): PipelineStatusMeta {
  return isPipelineStatus(s)
    ? PIPELINE_STATUS_META[s]
    : { label: s || 'Unknown', tone: 'muted', description: '' }
}

export const GATE_LABEL: Record<string, string> = {
  passing: 'Passing',
  failing: 'Failing',
  none: 'No gate yet',
}

export const FRESHNESS_LABEL: Record<string, string> = {
  running: 'Running',
  fresh: 'Fresh',
  stale: 'Stale',
  archived: 'Archived',
  never: 'Never ran',
}

export const HEALTH_REASON_LABEL: Record<string, string> = {
  scanner_errors: 'Scanners failed in the last run',
  outdated_runner: 'Runner older than the minimum supported version',
}

/** The fleet mode as the UI names it. */
export const MODE_LABEL: Record<FleetMode, string> = {
  daemon: 'Daemon',
  runner: 'Runner',
}

/** "the workflow file without its folder" for a compact cell. */
export function workflowFile(path: string | undefined): string {
  if (!path) return ''
  const i = path.lastIndexOf('/')
  return i >= 0 ? path.slice(i + 1) : path
}

/** The repository without its code host ("acme/api" from "github.com/acme/api"). */
export function repositoryPath(name: string | undefined): string {
  if (!name) return ''
  const i = name.indexOf('/')
  return i > 0 && name.slice(0, i).includes('.') ? name.slice(i + 1) : name
}

/** A cadence in words ("every 1 day", "every 6 hours"). */
export function cadenceLabel(seconds: number | undefined): string | null {
  if (!seconds || seconds <= 0) return null
  const h = seconds / 3600
  if (h < 1) return `every ${Math.max(1, Math.round(seconds / 60))} min`
  if (h < 48) {
    const n = Math.round(h)
    return `every ${n} ${n === 1 ? 'hour' : 'hours'}`
  }
  const d = Math.round(h / 24)
  return `every ${d} ${d === 1 ? 'day' : 'days'}`
}

export interface PipelineListFilters {
  status?: CIPipelineStatus[]
  includeInactive?: boolean
  search?: string
  provider?: string
  page?: number
  perPage?: number
}

/** GET /api/v1/ci/pipelines with its filters; exported for tests. */
export function pipelinesURL(base: string, f: PipelineListFilters = {}): string {
  const q = new URLSearchParams()
  if (f.status?.length) q.set('status', f.status.join(','))
  if (f.includeInactive) q.set('include_inactive', 'true')
  if (f.search) q.set('search', f.search)
  if (f.provider) q.set('provider', f.provider)
  q.set('page', String(f.page ?? 1))
  q.set('per_page', String(f.perPage ?? 25))
  return `${base}/pipelines?${q.toString()}`
}

export interface FleetListFilters {
  mode?: 'all' | FleetMode
  role?: string
  status?: string[]
  attention?: boolean
  includeInactive?: boolean
  search?: string
  page?: number
  perPage?: number
}

/** GET /api/v1/fleet with its filters; exported for tests. */
export function fleetURL(f: FleetListFilters = {}): string {
  const q = new URLSearchParams()
  q.set('mode', f.mode ?? 'all')
  if (f.role) q.set('role', f.role)
  if (f.status?.length) q.set('status', f.status.join(','))
  if (f.attention) q.set('attention', 'true')
  if (f.includeInactive) q.set('include_inactive', 'true')
  if (f.search) q.set('search', f.search)
  q.set('page', String(f.page ?? 1))
  q.set('per_page', String(f.perPage ?? 25))
  return `/api/v1/fleet?${q.toString()}`
}
