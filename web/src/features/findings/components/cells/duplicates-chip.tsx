'use client'

import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

export interface DuplicatesChipProps {
  /** Findings marked as duplicates of this one that the viewer can read. */
  count?: number
  /**
   * False inside another control (the title button, the phone card): no
   * focus stop or tooltip, the hint is the title and the accessible text.
   */
  interactive?: boolean
}

/**
 * "+2 dup" beside a finding title: the same issue was reported more times and
 * those findings were marked as duplicates of this one (they are closed, so
 * the open list does not show them). Only duplicates the viewer can read are
 * counted. Nothing renders for none.
 */
export function DuplicatesChip({ count, interactive = true }: DuplicatesChipProps) {
  const { t } = useTranslation()
  if (!count || count < 1) return null
  const hint =
    count === 1
      ? t('findings.list.duplicatesHintOne', '1 finding is marked as a duplicate of this one')
      : t('findings.list.duplicatesHint', '{count} findings are marked as duplicates of this one', {
          count,
        })
  const cls =
    'text-muted-foreground border-border inline-flex h-4 shrink-0 items-center rounded-sm border border-dashed px-1 text-meta tabular-nums'
  const text = t('findings.list.duplicatesChip', '+{count} dup', { count })
  if (!interactive) {
    return (
      <span data-slot="duplicates-chip" title={hint} className={cls}>
        <span aria-hidden>{text}</span>
        <span className="sr-only">{hint}</span>
      </span>
    )
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          data-slot="duplicates-chip"
          tabIndex={0}
          aria-label={hint}
          className={cn(
            cls,
            'focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none'
          )}
        >
          {text}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs text-xs">
        {hint}
      </TooltipContent>
    </Tooltip>
  )
}
