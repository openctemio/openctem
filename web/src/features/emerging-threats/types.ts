/**
 * Emerging threats: newly published or newly exploited CVEs that match
 * software the organization runs, ranked by an exploitation-weighted score
 * (ETS). The API contract is not in the generated types yet, so the wire
 * types live here.
 */

export type AlertLevel = 'immediate' | 'digest' | 'listed'
export type AlertTier = 'confirmed' | 'possible'
export type AlertState = 'new' | 'acknowledged' | 'remediating' | 'not_affected' | 'resolved'
export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low' | ''
export type AssetTier = 'confirmed' | 'likely' | 'possible'
export type RecommendedAction = 'patch_now' | 'confirm' | 'patch_within_sla'

export interface EmergingThreatSummary {
  id: string
  vuln_id: string
  title: string
  severity: AlertSeverity
  level: AlertLevel
  tier: AlertTier
  state: AlertState
  ets: number
  in_kev: boolean
  kev_ransomware: boolean
  epss: number | null
  confirmed_assets: number
  possible_assets: number
  internet_facing_assets: number
  last_event_kind: string
  event_at: string | null
  source_at: string | null
  created_at: string
  updated_at: string
}

export interface EtsBreakdown {
  exploitation: number
  severity: number
  exposure: number
  freshness: number
  /** Confidence multiplier, 0 to 1. */
  confidence: number
  total: number
}

export interface EmergingThreatAsset {
  asset_id: string
  asset_name: string
  asset_type: string
  tier: AssetTier
  confidence: number
  internet_facing: boolean
  criticality: string
  product: string
  version_seen: string
  finding_id: string
  finding_status: string
  task_id: string
}

export interface TimelineEvent {
  kind: string
  at: string
  source_at: string | null
  detail: Record<string, unknown> | null
}

export interface EmergingThreatDetail extends EmergingThreatSummary {
  ets_breakdown: EtsBreakdown
  recommended_action: RecommendedAction
  description: string
  cvss_score: number | null
  published_at: string | null
  kev_date_added: string
  state_reason: string
  state_note: string
  state_changed_at: string | null
  suppressed_until: string | null
  can_suppress: boolean
  assets: EmergingThreatAsset[]
  timeline: TimelineEvent[]
}

export interface EmergingThreatsSummaryCounts {
  open: number
  immediate: number
  digest: number
  listed: number
  kev: number
  internet_facing: number
}

export interface EmergingThreatsPage {
  data: EmergingThreatSummary[]
  total: number
  page: number
  per_page: number
  total_pages: number
  summary: EmergingThreatsSummaryCounts
}

export type StateFilter = 'open' | 'all' | AlertState
export interface ListFilters {
  level?: AlertLevel
  state?: StateFilter
  tier?: AlertTier
  internetOnly?: boolean
  search?: string
  page?: number
  perPage?: number
}

export type TargetState = 'acknowledged' | 'remediating' | 'new' | 'not_affected'

export const NOT_AFFECTED_REASONS = [
  'version_not_affected',
  'feature_not_used',
  'compensating_control',
  'wrong_product',
  'asset_decommissioned',
] as const
export type NotAffectedReason = (typeof NOT_AFFECTED_REASONS)[number]
export const MAX_NOTE_LENGTH = 500
export const MAX_TASK_TITLE_LENGTH = 200

export const LEVELS: AlertLevel[] = ['immediate', 'digest', 'listed']
export const STATE_FILTERS: StateFilter[] = [
  'open',
  'new',
  'acknowledged',
  'remediating',
  'not_affected',
  'resolved',
  'all',
]

/** Finding statuses a remediation task can still take. */
export const TASKABLE_FINDING_STATUSES = ['new', 'confirmed', 'in_progress', 'fix_applied']

/** The assets of an alert a new task can take, and the ones already in a task. */
export function splitTaskable(assets: EmergingThreatAsset[]): {
  eligible: EmergingThreatAsset[]
  alreadyInTask: EmergingThreatAsset[]
} {
  const eligible: EmergingThreatAsset[] = []
  const alreadyInTask: EmergingThreatAsset[] = []
  for (const a of assets) {
    if (!a.finding_id || !TASKABLE_FINDING_STATUSES.includes(a.finding_status)) continue
    if (a.task_id) alreadyInTask.push(a)
    else eligible.push(a)
  }
  return { eligible, alreadyInTask }
}

/** "CVE-2026-1: title", cut to the task title limit. */
export function taskTitle(vulnId: string, title: string): string {
  const full = title.trim() ? `${vulnId}: ${title.trim()}` : vulnId
  return Array.from(full).slice(0, MAX_TASK_TITLE_LENGTH).join('')
}

// ---------------------------------------------------------------- settings

export interface EmergingThreatsSettings {
  disabled: boolean
  immediate_threshold: number
  digest_threshold: number
  digest_hour: number
  quiet_hours: { enabled: boolean; start_hour: number; end_hour: number }
  quiet_override: number
  include_possible_in_immediate: boolean
  asset_names_in_messages: boolean
}

export const SETTINGS_BOUNDS = {
  immediate_threshold: [60, 90],
  digest_threshold: [20, 60],
  digest_hour: [0, 23],
  quiet_hour: [0, 23],
  quiet_override: [70, 100],
} as const

/** Field name to the i18n key of its problem. */
export type SettingsErrors = Partial<Record<string, string>>

const isInt = (n: unknown): n is number => typeof n === 'number' && Number.isInteger(n)
const within = (n: unknown, [lo, hi]: readonly [number, number]): n is number =>
  isInt(n) && n >= lo && n <= hi

/** Client-side bound checks; the API checks again. Values are i18n keys. */
export function validateSettings(s: EmergingThreatsSettings): SettingsErrors {
  const e: SettingsErrors = {}
  const b = SETTINGS_BOUNDS
  if (!within(s.immediate_threshold, b.immediate_threshold))
    e.immediate_threshold = 'emergingThreats.settings.err.immediateThreshold'
  if (!within(s.digest_threshold, b.digest_threshold))
    e.digest_threshold = 'emergingThreats.settings.err.digestThreshold'
  else if (
    within(s.immediate_threshold, b.immediate_threshold) &&
    s.digest_threshold >= s.immediate_threshold
  )
    e.digest_threshold = 'emergingThreats.settings.err.digestBelowImmediate'
  if (!within(s.digest_hour, b.digest_hour)) e.digest_hour = 'emergingThreats.settings.err.hour'
  if (!within(s.quiet_override, b.quiet_override))
    e.quiet_override = 'emergingThreats.settings.err.quietOverride'
  if (s.quiet_hours.enabled) {
    if (!within(s.quiet_hours.start_hour, b.quiet_hour))
      e.quiet_start = 'emergingThreats.settings.err.hour'
    if (!within(s.quiet_hours.end_hour, b.quiet_hour))
      e.quiet_end = 'emergingThreats.settings.err.hour'
    if (!e.quiet_start && !e.quiet_end && s.quiet_hours.start_hour === s.quiet_hours.end_hour)
      e.quiet_end = 'emergingThreats.settings.err.quietSame'
  }
  return e
}

export function formatHour(h: number): string {
  return `${String(h).padStart(2, '0')}:00`
}
