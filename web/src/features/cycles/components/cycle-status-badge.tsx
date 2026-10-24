import { StatusLozenge } from '@/components/ui/status-lozenge'
import { CheckCircleGlyph, HalfCircleGlyph, RingDotGlyph } from '@/components/ui/status-glyphs'
import type { StatusGlyph } from '@/components/ui/status-glyphs'
import { Clock } from 'lucide-react'
import type { StatusTone } from '@/lib/status-colors'
import { useTranslation } from '@/context/i18n-provider'
import type { CtemCycleStatus } from '../types'

/**
 * A cycle moves through planning, active, review and closed (research/247
 * section 4): planning is open, active is in progress, review waits for a
 * person, closed is done. The map holds no classes.
 */
export const CYCLE_STATUS_TONE: Record<CtemCycleStatus, { tone: StatusTone; icon: StatusGlyph }> = {
  planning: { tone: 'open', icon: RingDotGlyph },
  active: { tone: 'progress', icon: HalfCircleGlyph },
  review: { tone: 'waiting', icon: Clock },
  closed: { tone: 'resolved', icon: CheckCircleGlyph },
}

/** The cycle status in words, in the console language. */
export function useCycleStatusLabel() {
  const { t } = useTranslation()
  return (status: string) => t(`scoping.cycleStatus.${status}`, status)
}

export function CycleStatusBadge({
  status,
  className,
}: {
  status: CtemCycleStatus
  className?: string
}) {
  const label = useCycleStatusLabel()
  const cfg = CYCLE_STATUS_TONE[status]
  return (
    <StatusLozenge
      tone={cfg?.tone ?? 'closed'}
      icon={cfg?.icon}
      label={label(status)}
      value={status}
      className={className}
    />
  )
}
