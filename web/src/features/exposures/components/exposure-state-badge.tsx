'use client'

import { StatusLozenge } from '@/components/ui/status-lozenge'
import {
  CheckCircleGlyph,
  HalfCircleGlyph,
  RingDotGlyph,
  SlashedCircleGlyph,
} from '@/components/ui/status-glyphs'
import type { StatusGlyph } from '@/components/ui/status-glyphs'
import { ShieldAlert } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import type { StatusTone } from '@/lib/status-colors'
import type { ExposureState } from '@/lib/api/exposure-types'

/** Exposure state on the shared status tones: active and in progress are open work, resolved is done. */
const EXPOSURE_STATE: Record<
  ExposureState,
  { tone: StatusTone; icon: StatusGlyph; label: string }
> = {
  active: { tone: 'open', icon: RingDotGlyph, label: 'Active' },
  in_progress: { tone: 'progress', icon: HalfCircleGlyph, label: 'In progress' },
  resolved: { tone: 'resolved', icon: CheckCircleGlyph, label: 'Resolved' },
  accepted: { tone: 'accepted', icon: ShieldAlert, label: 'Accepted' },
  false_positive: { tone: 'closed', icon: SlashedCircleGlyph, label: 'False positive' },
}

/** The one exposure state label (same lozenge as a finding status). */
export function ExposureStateBadge({ state }: { state: ExposureState }) {
  const { t } = useTranslation()
  const cfg = EXPOSURE_STATE[state]
  if (!cfg) return null
  return (
    <StatusLozenge
      tone={cfg.tone}
      icon={cfg.icon}
      label={t(`exposures.state.${state}`, cfg.label)}
      value={state}
    />
  )
}
