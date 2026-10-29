'use client'

import { useTranslation } from '@/context/i18n-provider'
import { RemovableFilterChip } from '@/features/shared/components/removable-filter-chip'
import { toDisplayText } from '@/lib/untrusted-text'
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
      return `${name}: ${toDisplayText(valueLabel(field, filter.values[0] ?? ''), 80)}`
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
  return (
    <RemovableFilterChip
      text={text}
      locked={Boolean(filter.locked)}
      lockedHint={t(
        'findings.filter.locked',
        'From the saved view. Edit or switch the view to change it.'
      )}
      onRemove={onRemove ? () => onRemove(filter) : undefined}
      removeLabel={t('findings.filter.remove', 'Remove filter {filter}', { filter: text })}
    />
  )
}
