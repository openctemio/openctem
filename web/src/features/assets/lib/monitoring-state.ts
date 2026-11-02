/**
 * The one derived monitoring state of an asset (API `monitoring_state`, see
 * api/docs/architecture/exposure-taxonomy.md): where the asset stands in the
 * external attack surface lifecycle. In the API's precedence order.
 */
import type { Tone } from '@/components/ui/tone-chip'

export const MONITORING_STATES = [
  'monitored',
  'not_monitored',
  'pending_decision',
  'unvalidated',
  'irrelevant',
  'inactive',
  'out_of_scope',
] as const

export type MonitoringState = (typeof MONITORING_STATES)[number]

export function isMonitoringState(v: string | undefined): v is MonitoringState {
  return !!v && (MONITORING_STATES as readonly string[]).includes(v)
}

export const MONITORING_STATE_FALLBACK: Record<MonitoringState, string> = {
  monitored: 'Monitored',
  not_monitored: 'Not monitored',
  pending_decision: 'Pending decision',
  unvalidated: 'Unvalidated',
  irrelevant: 'Irrelevant',
  inactive: 'Inactive',
  out_of_scope: 'Out of scope',
}

export const MONITORING_STATE_HINT: Record<MonitoringState, string> = {
  monitored: 'The platform watches this asset.',
  not_monitored:
    'Kept for reference, or no scope entry covers it and unclassified assets are not scanned.',
  pending_decision: 'Someone needs to decide whether this asset is yours.',
  unvalidated: 'Found by discovery with too little evidence that it is yours.',
  irrelevant: 'Marked as not yours.',
  inactive: 'Inactive or archived.',
  out_of_scope: 'Yours, but excluded from scanning (do not scan, or retired).',
}

/** Attention tone per state: work to do is caution, settled states are quiet. */
export const MONITORING_STATE_TONE: Record<MonitoringState, Tone> = {
  monitored: 'ok',
  not_monitored: 'neutral',
  pending_decision: 'caution',
  unvalidated: 'caution',
  irrelevant: 'quiet',
  inactive: 'quiet',
  out_of_scope: 'neutral',
}
