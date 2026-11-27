'use client'

import { cloneElement, useState, type ReactElement } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { RemovableFilterChip } from '@/features/shared/components/removable-filter-chip'
import { ResponsivePopover } from '@/features/shared/components/responsive-popover'
import { toDisplayText } from '@/lib/untrusted-text'
import { FieldEditor } from './field-editor'
import {
  isEditableField,
  type ActiveFilter,
  type FieldContract,
  type FilterContract,
  type FilterOp,
} from './model'
import { useFilterLabels } from './use-filter-labels'

/** What a chip needs to edit its filter in place. */
export interface FilterChipEdit {
  /**
   * The filter contract, once loaded: the editor takes the field's operators
   * and values from it, never from the page's own list of fields.
   */
  contract: FilterContract | undefined
  contractFailed: boolean
  /** An editor opened or closed (the page loads the contract while one is open). */
  onOpenChange?: (open: boolean) => void
  /** Replace `filter` with this operator and these values on `field`. */
  onApply: (filter: ActiveFilter, field: FieldContract, op: FilterOp, values: string[]) => void
}

interface FilterChipProps {
  filter: ActiveFilter
  field: FieldContract
  /** Removes the filter; absent on a locked chip. */
  onRemove?: (filter: ActiveFilter) => void
  /** Lets the chip's text open the filter's editor; never used by a locked chip. */
  edit?: FilterChipEdit
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
    // "Severity: Critical, High": a plain match reads as label and value; other
    // operators keep their word ("Status is not Accepted", "EPSS ≥ 0.5").
    const plain =
      filter.op === 'in' ||
      (filter.op === 'eq' && field.type !== 'number' && field.type !== 'integer')
    if (plain)
      return t('findings.filter.chipValue', '{field}: {values}', { field: name, values: list })
    return `${name} ${opLabel(filter.op, field)} ${list}`
  }
}

/**
 * One active filter. A chip that comes from the open saved view shows a lock
 * and has no remove button: you switch or edit the view instead. Any other
 * chip of a field Add filter offers is edited from its text: it opens the
 * editor Add filter shows for the field, on the chip's operator and values,
 * anchored to the chip (a bottom sheet on a phone). Applying replaces the
 * filter; Escape or a click outside changes nothing.
 */
export function FilterChip({ filter, field, onRemove, edit }: FilterChipProps) {
  const { t } = useTranslation()
  const labels = useFilterLabels()
  const text = useChipText()(filter, field)
  const [open, setOpenState] = useState(false)
  const editable = !!edit && !filter.locked && isEditableField(field)
  const setOpen = (next: boolean) => {
    setOpenState(next)
    edit?.onOpenChange?.(next)
  }
  // The field as the contract describes it to this viewer.
  const loaded = edit?.contract?.fields.find((f) => f.name === field.name)
  // Kept while the editor closes: the page lets go of the contract then.
  const [kept, setKept] = useState(loaded)
  if (loaded && loaded !== kept) setKept(loaded)
  const described = loaded ?? (open ? undefined : kept)

  const editWith = (button: ReactElement) => (
    <ResponsivePopover
      open={open}
      onOpenChange={setOpen}
      title={t('findings.filter.editTitle', 'Edit {field} filter', {
        field: labels.fieldLabel(field.name),
      })}
      className="w-80"
      // The page finds the chip again by its param, to hand focus back.
      trigger={cloneElement(button as ReactElement<Record<string, unknown>>, {
        'data-filter-param': filter.param,
      })}
    >
      {described && edit ? (
        <FieldEditor
          field={described}
          labels={labels}
          initial={{ op: filter.op, values: filter.values }}
          onApply={(op, values) => {
            setOpen(false)
            edit.onApply(filter, described, op, values)
          }}
        />
      ) : edit?.contractFailed ? (
        <p className="px-3 py-4 text-sm text-destructive" role="alert">
          {t('findings.filter.loadFailed', 'The filters could not be loaded.')}
        </p>
      ) : edit?.contract ? (
        <p className="px-3 py-4 text-sm text-muted-foreground" role="alert">
          {t('findings.filter.notEditable', 'This filter cannot be changed here.')}
        </p>
      ) : (
        <p className="px-3 py-4 text-sm text-muted-foreground" role="status">
          {t('findings.filter.loading', 'Loading filters…')}
        </p>
      )}
    </ResponsivePopover>
  )

  return (
    <RemovableFilterChip
      editWith={editable ? editWith : undefined}
      editLabel={t('findings.filter.edit', 'Edit filter {filter}', { filter: text })}
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
