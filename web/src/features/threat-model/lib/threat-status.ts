import { ShieldAlert, ShieldCheck } from 'lucide-react'
import {
  CheckCircleGlyph,
  DashedCircleGlyph,
  RingDotGlyph,
  type StatusGlyph,
} from '@/components/ui/status-glyphs'
import type { StatusTone } from '@/lib/status-colors'
import type { ThreatStatus } from '../types'

/**
 * Status of a derived threat on the shared workflow tones (research/247
 * section 4): open is open work, mitigated and covered are done (covered by a
 * compensating control, with a shield), accepted is a risk decision, and
 * theoretical (a technique that applies, with no evidence yet) is untouched.
 * The map holds no classes; colour comes from `lib/status-colors`.
 */
export interface ThreatStatusStyle {
  /** i18n key of the status label. */
  labelKey: string
  tone: StatusTone
  icon: StatusGlyph
}

export const THREAT_STATUS_STYLES: Record<ThreatStatus, ThreatStatusStyle> = {
  open: { labelKey: 'threatModel.status.open', tone: 'open', icon: RingDotGlyph },
  mitigated: { labelKey: 'threatModel.status.mitigated', tone: 'resolved', icon: CheckCircleGlyph },
  covered: { labelKey: 'threatModel.status.covered', tone: 'resolved', icon: ShieldCheck },
  accepted: { labelKey: 'threatModel.status.accepted', tone: 'accepted', icon: ShieldAlert },
  theoretical: {
    labelKey: 'threatModel.status.theoretical',
    tone: 'triage',
    icon: DashedCircleGlyph,
  },
}

/**
 * Concrete hex for each status, for the ATT&CK Navigator layer export, where a
 * literal color is required and a class cannot be used.
 */
export const THREAT_STATUS_HEX: Record<ThreatStatus, string> = {
  open: '#ef4444', // red-500
  mitigated: '#22c55e', // green-500
  covered: '#3b82f6', // blue-500
  accepted: '#9ca3af', // gray-400 (muted)
  theoretical: '#94a3b8', // slate-400
}

export function getThreatStatusHex(status: ThreatStatus): string {
  return THREAT_STATUS_HEX[status] ?? THREAT_STATUS_HEX.theoretical
}

/** All statuses in a sensible display/severity order. */
export const THREAT_STATUS_ORDER: ThreatStatus[] = [
  'open',
  'theoretical',
  'covered',
  'mitigated',
  'accepted',
]

export function getThreatStatusStyle(status: ThreatStatus): ThreatStatusStyle {
  return (
    THREAT_STATUS_STYLES[status] ?? {
      labelKey: `threatModel.status.${status}`,
      tone: 'closed',
      icon: DashedCircleGlyph,
    }
  )
}
