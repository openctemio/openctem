'use client'

import { Lock, X } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { toDisplayText } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'
import type { ActiveFilter, FieldContract } from './model'
import { useFilterLabels } from './use-filter-labels'

interface FilterChipProps {
  filter: ActiveFilter
  field: FieldContract
  /** Removes the filter; absent on a locked chip. */
  onRemove?: (filter: ActiveFilter) => void
}

/** The sentence a chip reads: "Severity is Critical, High". */
export function useChipText() {
  const { fieldLabel, opLabel, valueLabel } = useFilterLabels()
  const { t } = useTranslation()
  return (filter: ActiveFilter, field: FieldContract) => {
    const name = fieldLabel(field.name)
    if (filter.op === 'is_null') {
      return filter.values[0] === 'true'
        ? t('findings.filter.isEmpty', '{field} is empty', { field: name })
        : t('findings.filter.isSet', '{field} is set', { field: name })
    }
    // A true/false field reads "Known exploited: Yes", not "...is Yes".
    if (field.type === 'boolean') {
      return `${name}: ${valueLabel(field, filter.values[0] ?? '')}`
    }
    const shown = filter.values.map((v) => toDisplayText(valueLabel(field, v), 80))
    const list =
      shown.length > 3 ? `${shown.slice(0, 3).join(', ')} +${shown.length - 3}` : shown.join(', ')
    return `${name} ${opLabel(filter.op, field)} ${list}`
  }
}

/**
 * One active filter. A chip that comes from the open saved view shows a lock
 * and has no remove button: you switch or edit the view instead.
 */
export function FilterChip({ filter, field, onRemove }: FilterChipProps) {
  const { t } = useTranslation()
  const text = useChipText()(filter, field)
  const locked = Boolean(filter.locked)
  const lockedHint = t(
    'findings.filter.locked',
    'From the saved view. Edit or switch the view to change it.'
  )
  return (
    <span
      data-testid="filter-chip"
      data-locked={locked ? 'true' : undefined}
      className={cn(
        'inline-flex max-w-full items-center gap-1 rounded-full border bg-muted/50 py-0.5 text-xs',
        locked ? 'ps-2 pe-2' : 'ps-2.5 pe-1'
      )}
    >
      {locked && (
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="inline-flex" role="img" aria-label={lockedHint}>
              <Lock className="size-3 text-muted-foreground" aria-hidden />
            </span>
          </TooltipTrigger>
          <TooltipContent>{lockedHint}</TooltipContent>
        </Tooltip>
      )}
      <span dir="auto" className="min-w-0 truncate [unicode-bidi:isolate]" title={text}>
        {text}
      </span>
      {!locked && onRemove && (
        <button
          type="button"
          onClick={() => onRemove(filter)}
          aria-label={t('findings.filter.remove', 'Remove filter {filter}', { filter: text })}
          className="inline-flex size-5 shrink-0 items-center justify-center rounded-full text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <X className="size-3" aria-hidden />
        </button>
      )}
    </span>
  )
}
