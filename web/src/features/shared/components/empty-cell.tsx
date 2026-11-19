import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'

/**
 * The one look of a table cell with nothing to show: a muted `—` with a hover
 * text saying why (ui-style-contract §7, "Unknown facts"). Tables use it
 * instead of a hand-written dash; phone cards, sheets and detail pages render
 * nothing for an empty value (a label without a value is left out).
 */
export function EmptyCell({ title, className }: { title?: string; className?: string }) {
  const { t } = useTranslation()
  return (
    <span
      data-slot="empty-cell"
      className={cn('text-muted-foreground', className)}
      title={title ?? t('assets.facts.notCollectedTitle', 'Not collected')}
    >
      —
    </span>
  )
}
