/**
 * One registry of status values and how they look: per domain, each value
 * maps to a tone and the i18n key of its label. StatusChip
 * (features/shared/components/status-chip.tsx) reads it, so a status reads
 * the same on every page (a draft campaign is "Draft", never "Open").
 */

export type StatusTone =
  'neutral' | 'info' | 'progress' | 'success' | 'warning' | 'danger' | 'muted'

export interface StatusEntry {
  tone: StatusTone
  labelKey: string
}

export const STATUS_TONES = {
  remediationCampaign: {
    draft: { tone: 'neutral', labelKey: 'remediationCampaigns.status.draft' },
    active: { tone: 'progress', labelKey: 'remediationCampaigns.status.active' },
    completed: { tone: 'success', labelKey: 'remediationCampaigns.status.completed' },
    canceled: { tone: 'muted', labelKey: 'remediationCampaigns.status.canceled' },
  },
  remediationTask: {
    open: { tone: 'neutral', labelKey: 'remediationHub.state.open' },
    in_progress: { tone: 'progress', labelKey: 'remediationHub.state.in_progress' },
    verifying: { tone: 'info', labelKey: 'remediationHub.state.verifying' },
    on_hold: { tone: 'warning', labelKey: 'remediationHub.state.on_hold' },
    done: { tone: 'success', labelKey: 'remediationHub.state.done' },
    closed_unverified: { tone: 'warning', labelKey: 'remediationHub.state.closed_unverified' },
    canceled: { tone: 'muted', labelKey: 'remediationHub.state.canceled' },
    archived: { tone: 'muted', labelKey: 'remediationHub.state.archived' },
  },
} as const satisfies Record<string, Record<string, StatusEntry>>

export type StatusDomain = keyof typeof STATUS_TONES

/** The entry of a status value, or undefined for a value the registry does not know. */
export function statusEntry(domain: StatusDomain, value: string): StatusEntry | undefined {
  const map: Record<string, StatusEntry> = STATUS_TONES[domain]
  return Object.prototype.hasOwnProperty.call(map, value) ? map[value] : undefined
}

/** Theme-token classes of each tone: the tinted chip and its dot. */
export const STATUS_TONE_CLASS: Record<StatusTone, { chip: string; dot: string }> = {
  neutral: { chip: 'bg-secondary text-secondary-foreground', dot: 'bg-foreground/60' },
  // Work in motion is the filled blue; a waiting-on-a-check state is the outlined blue.
  info: { chip: 'border-info/50 bg-transparent text-info', dot: 'bg-info' },
  progress: { chip: 'bg-info/15 text-info', dot: 'bg-info' },
  success: { chip: 'bg-success/15 text-success', dot: 'bg-success' },
  warning: { chip: 'bg-warning/15 text-warning', dot: 'bg-warning' },
  danger: { chip: 'bg-destructive/15 text-destructive', dot: 'bg-destructive' },
  muted: { chip: 'bg-muted text-muted-foreground', dot: 'bg-muted-foreground' },
}
