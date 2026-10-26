/**
 * One registry of workflow status values and how they read: per domain, each
 * value maps to a tone (the categories of lib/status-colors.ts, the one colour
 * source), a progression icon and the i18n key of its label. StatusChip
 * (features/shared/components/status-chip.tsx) reads it and renders a
 * StatusLozenge, so a status reads the same on every page (a draft campaign is
 * "Draft", never "Open"). This file holds no colour.
 */

import type { StatusTone } from '@/lib/status-colors'
import {
  CheckCircleGlyph,
  DashedCircleGlyph,
  HalfCircleGlyph,
  RingDotGlyph,
  SlashedCircleGlyph,
  ThreeQuarterCircleGlyph,
  type StatusGlyph,
} from '@/components/ui/status-glyphs'
import { Clock } from 'lucide-react'

export type { StatusTone }

export interface StatusEntry {
  tone: StatusTone
  icon: StatusGlyph
  labelKey: string
}

export const STATUS_TONES = {
  remediationCampaign: {
    draft: {
      tone: 'triage',
      icon: DashedCircleGlyph,
      labelKey: 'remediationCampaigns.status.draft',
    },
    active: {
      tone: 'progress',
      icon: HalfCircleGlyph,
      labelKey: 'remediationCampaigns.status.active',
    },
    completed: {
      tone: 'resolved',
      icon: CheckCircleGlyph,
      labelKey: 'remediationCampaigns.status.completed',
    },
    canceled: {
      tone: 'closed',
      icon: SlashedCircleGlyph,
      labelKey: 'remediationCampaigns.status.canceled',
    },
  },
  remediationTask: {
    open: { tone: 'open', icon: RingDotGlyph, labelKey: 'remediationHub.state.open' },
    in_progress: {
      tone: 'progress',
      icon: HalfCircleGlyph,
      labelKey: 'remediationHub.state.in_progress',
    },
    verifying: {
      tone: 'progress',
      icon: ThreeQuarterCircleGlyph,
      labelKey: 'remediationHub.state.verifying',
    },
    on_hold: { tone: 'waiting', icon: Clock, labelKey: 'remediationHub.state.on_hold' },
    done: { tone: 'resolved', icon: CheckCircleGlyph, labelKey: 'remediationHub.state.done' },
    closed_unverified: {
      tone: 'closed',
      icon: SlashedCircleGlyph,
      labelKey: 'remediationHub.state.closed_unverified',
    },
    canceled: {
      tone: 'closed',
      icon: SlashedCircleGlyph,
      labelKey: 'remediationHub.state.canceled',
    },
    archived: {
      tone: 'closed',
      icon: SlashedCircleGlyph,
      labelKey: 'remediationHub.state.archived',
    },
  },
  // Organization sensor enrollment tokens.
  enrollmentToken: {
    active: { tone: 'progress', icon: HalfCircleGlyph, labelKey: 'sensors.tokens.state.active' },
    exhausted: {
      tone: 'closed',
      icon: CheckCircleGlyph,
      labelKey: 'sensors.tokens.state.exhausted',
    },
    expired: { tone: 'closed', icon: Clock, labelKey: 'sensors.tokens.state.expired' },
    revoked: {
      tone: 'closed',
      icon: SlashedCircleGlyph,
      labelKey: 'sensors.tokens.state.revoked',
    },
  },
} as const satisfies Record<string, Record<string, StatusEntry>>

export type StatusDomain = keyof typeof STATUS_TONES

/** The entry of a status value, or undefined for a value the registry does not know. */
export function statusEntry(domain: StatusDomain, value: string): StatusEntry | undefined {
  const map: Record<string, StatusEntry> = STATUS_TONES[domain]
  return Object.prototype.hasOwnProperty.call(map, value) ? map[value] : undefined
}
