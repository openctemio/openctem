'use client'

import { useMemo, useState } from 'react'
import {
  AddFilterButton,
  ShowFilterPanelButton,
  useAddFilterShortcut,
} from '@/features/shared/components/filter-button'
import { ResponsivePopover } from '@/features/shared/components/responsive-popover'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import { useTranslation } from '@/context/i18n-provider'
import { FieldEditor } from './field-editor'
import {
  pickableFields,
  type FieldContract,
  type FieldGroup,
  type FilterContract,
  type FilterOp,
} from './model'
import { useFilterLabels } from './use-filter-labels'

const GROUP_LABELS: Record<FieldGroup, [string, string]> = {
  exploitation: ['findings.filter.group.exploitation', 'Exploitation'],
  finding: ['findings.filter.group.finding', 'Finding'],
  asset: ['findings.filter.group.asset', 'Asset'],
  work: ['findings.filter.group.work', 'Work'],
  other: ['findings.filter.group.other', 'Other'],
}

interface AddFilterPopoverProps {
  /** The contract, once loaded (the popover asks the page to load it when opened). */
  contract: FilterContract | undefined
  contractLoading: boolean
  contractFailed: boolean
  canReadAssets: boolean
  /** Fields the open saved view already sets: a filter on one would override the view. */
  lockedFields?: ReadonlySet<string>
  onOpenChange?: (open: boolean) => void
  onApply: (field: FieldContract, op: FilterOp, values: string[]) => void
  /** Open the list's facet panel (its last row), where the list has one. */
  onOpenPanel?: () => void
}

/**
 * Add filter: a searchable, grouped list of every field the API offers this
 * viewer, then an editor typed by the field (choices for an enum, an operator
 * and a number, quick date ranges, yes / no...). It is generated from the
 * filter contract, so a field the API adds appears here with no web change.
 * Pressing `f` outside a text field opens it.
 */
export function AddFilterPopover({
  contract,
  contractLoading,
  contractFailed,
  canReadAssets,
  lockedFields,
  onOpenChange,
  onApply,
  onOpenPanel,
}: AddFilterPopoverProps) {
  const { t } = useTranslation()
  const labels = useFilterLabels()
  const [open, setOpenState] = useState(false)
  const [picked, setPicked] = useState<FieldContract | null>(null)

  const setOpen = (next: boolean) => {
    setOpenState(next)
    if (!next) setPicked(null)
    onOpenChange?.(next)
  }

  useAddFilterShortcut(() => {
    setOpenState(true)
    onOpenChange?.(true)
  })

  const groups = useMemo(
    () => (contract ? pickableFields(contract, { canReadAssets }) : []),
    [contract, canReadAssets]
  )

  return (
    <ResponsivePopover
      open={open}
      onOpenChange={setOpen}
      title={t('findings.filter.add', 'Add filter')}
      className="w-80"
      trigger={<AddFilterButton />}
    >
      {picked ? (
        <FieldEditor
          key={picked.name}
          field={picked}
          labels={labels}
          onBack={() => setPicked(null)}
          onApply={(op, values) => {
            onApply(picked, op, values)
            setOpen(false)
          }}
        />
      ) : (
        <Command>
          <CommandInput placeholder={t('findings.filter.searchFields', 'Search fields…')} />
          <CommandList>
            {contractLoading && !contract && (
              <p className="px-3 py-4 text-sm text-muted-foreground" role="status">
                {t('findings.filter.loading', 'Loading filters…')}
              </p>
            )}
            {contractFailed && !contract && (
              <p className="px-3 py-4 text-sm text-destructive" role="alert">
                {t('findings.filter.loadFailed', 'The filters could not be loaded.')}
              </p>
            )}
            {contract && (
              <CommandEmpty>{t('findings.filter.noField', 'No matching field')}</CommandEmpty>
            )}
            {groups.map(({ group, fields }) => (
              <CommandGroup key={group} heading={t(...GROUP_LABELS[group])}>
                {fields.map((f) => {
                  const label = labels.fieldLabel(f.name)
                  const locked = lockedFields?.has(f.name) ?? false
                  return (
                    <CommandItem
                      key={f.name}
                      value={`${label} ${f.name}`}
                      disabled={locked}
                      onSelect={() => setPicked(f)}
                    >
                      {label}
                      {locked && (
                        <span className="ms-auto text-xs text-muted-foreground">
                          {t('findings.filter.setByView', 'Set by the saved view')}
                        </span>
                      )}
                    </CommandItem>
                  )
                })}
              </CommandGroup>
            ))}
          </CommandList>
          {onOpenPanel && (
            <ShowFilterPanelButton
              onClick={() => {
                setOpen(false)
                onOpenPanel()
              }}
            />
          )}
        </Command>
      )}
    </ResponsivePopover>
  )
}
