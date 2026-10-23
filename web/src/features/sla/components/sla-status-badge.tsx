import { Timer } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import { slaStateClass } from '@/lib/sla-colors'
import { SLA_STATUS_LABELS, type SLAStatus } from '@/features/repositories/types/repository.types'

/**
 * SLA status pill. Colours come from the one SLA map in lib/sla-colors.ts.
 *
 * Backend status values (vulnerability value_objects.go): on_track | warning |
 * overdue | exceeded | not_applicable.
 */
export function SlaStatusBadge({
  status,
  className,
}: {
  status?: string | null
  className?: string
}) {
  const { t } = useTranslation()
  const key = (status as SLAStatus) || 'not_applicable'
  const fallback = SLA_STATUS_LABELS[key] ?? SLA_STATUS_LABELS.not_applicable
  const label = t(`findings.sla.${SLA_STATUS_LABELS[key] ? key : 'not_applicable'}`, fallback)

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium',
        slaStateClass(status),
        className
      )}
    >
      <Timer className="h-3 w-3" />
      {label}
    </span>
  )
}
