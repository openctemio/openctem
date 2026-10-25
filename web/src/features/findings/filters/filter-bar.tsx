'use client'

import { useMemo, type ReactElement, type ReactNode } from 'react'
import { AlertCircle, X } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { FilterChipsRow } from '@/features/shared/components/filter-chips-row'
import { useTranslation } from '@/context/i18n-provider'
import { toDisplayText } from '@/lib/untrusted-text'
import { AddFilterPopover } from './add-filter-popover'
import { FilterChip } from './filter-chip'
import {
  readFilters,
  viewFields,
  viewFilters,
  withFilter,
  withoutParam,
  type FieldContract,
  type FilterContract,
  type FilterOp,
} from './model'

interface FilterBarProps {
  /** The page URL's query. */
  search: URLSearchParams
  /** The contract to read chips with (the loaded one plus the page-owned fields). */
  contract: FilterContract
  /** The picker's contract: only the loaded one, so it never offers the fallback subset. */
  pickerContract: FilterContract | undefined
  contractLoading: boolean
  contractFailed: boolean
  /** Params something else draws (the context chips). */
  skip: ReadonlySet<string>
  /** The open saved view's filter: its chips are locked. */
  viewFilter?: Record<string, unknown>
  canReadAssets: boolean
  /** The context chips (an asset, a scan...), drawn first. */
  leading?: ReactNode
  onPickerOpenChange: (open: boolean) => void
  /** Navigate to a new query (the page replaces the URL). */
  onSearchChange: (next: URLSearchParams) => void
  /** The open saved view differs from what is stored: Clear becomes "Reset to view". */
  viewChanged?: boolean
  /** Go back to the open saved view as stored. */
  onResetToView?: () => void
  /** "1,284 findings", pinned at the end of the row. */
  resultLabel?: string
}

/**
 * Every active filter as a chip, then Add filter. Chips from the open saved
 * view come first and are locked; a param no registry field knows is shown as
 * an unknown filter to remove, never silently ignored.
 */
export function FilterBar({
  search,
  contract,
  pickerContract,
  contractLoading,
  contractFailed,
  skip,
  viewFilter,
  canReadAssets,
  leading,
  onPickerOpenChange,
  onSearchChange,
  viewChanged,
  onResetToView,
  resultLabel,
}: FilterBarProps) {
  const { t } = useTranslation()
  const fieldOf = (name: string): FieldContract | undefined =>
    contract.fields.find((f) => f.name === name)

  const { filters, unknown } = useMemo(
    () => readFilters(search, contract, skip),
    [search, contract, skip]
  )
  const fromView = useMemo(() => viewFilters(viewFilter, contract), [viewFilter, contract])
  const lockedFields = useMemo(() => viewFields(viewFilter), [viewFilter])

  const chips: ReactElement[] = [
    ...(fromView.complex
      ? [
          <span
            key="view-complex"
            data-testid="filter-chip"
            data-locked="true"
            className="inline-flex items-center rounded-full border bg-muted/50 px-2 py-0.5 text-xs"
          >
            {t('findings.filter.viewConditions', 'Conditions from the saved view')}
          </span>,
        ]
      : []),
    ...fromView.filters.flatMap((f) => {
      const field = fieldOf(f.field)
      return field ? [<FilterChip key={`view-${f.param}`} filter={f} field={field} />] : []
    }),
    ...filters.flatMap((f) => {
      const field = fieldOf(f.field)
      return field
        ? [
            <FilterChip
              key={f.param}
              filter={f}
              field={field}
              onRemove={(x) => onSearchChange(withoutParam(search, x.param))}
            />,
          ]
        : []
    }),
    ...unknown.map((param) => (
      <span
        key={`unknown-${param}`}
        data-testid="filter-chip-unknown"
        className="inline-flex max-w-full items-center gap-1 rounded-full border border-destructive/40 bg-destructive/5 ps-2.5 pe-1 py-0.5 text-xs"
      >
        <span dir="auto" className="min-w-0 truncate [unicode-bidi:isolate]">
          {t('findings.filter.unknown', 'Unknown filter “{param}”', {
            param: toDisplayText(param, 40),
          })}
        </span>
        <button
          type="button"
          onClick={() => onSearchChange(withoutParam(search, param))}
          aria-label={t('findings.filter.removeUnknown', 'Remove unknown filter {param}', {
            param: toDisplayText(param, 40),
          })}
          className="inline-flex size-5 shrink-0 items-center justify-center rounded-full text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <X className="size-3" aria-hidden />
        </button>
      </span>
    )),
  ]

  const clearAll = () => {
    let next = search
    for (const f of filters) next = withoutParam(next, f.param)
    for (const p of unknown) next = withoutParam(next, p)
    onSearchChange(next)
  }

  return (
    <FilterChipsRow
      data-testid="findings-filter-bar"
      leading={leading}
      chips={chips}
      trailing={
        <>
          <AddFilterPopover
            contract={pickerContract}
            contractLoading={contractLoading}
            contractFailed={contractFailed}
            canReadAssets={canReadAssets}
            lockedFields={lockedFields}
            onOpenChange={onPickerOpenChange}
            onApply={(field: FieldContract, op: FilterOp, values: string[]) =>
              onSearchChange(withFilter(search, field, op, values))
            }
          />
          {viewChanged && onResetToView ? (
            <Button
              variant="ghost"
              size="sm"
              className="h-7 px-2 text-xs text-muted-foreground"
              onClick={onResetToView}
            >
              {t('findings.filter.resetToView', 'Reset to view')}
            </Button>
          ) : filters.length + unknown.length > 1 ? (
            <Button
              variant="ghost"
              size="sm"
              className="h-7 px-2 text-xs text-muted-foreground"
              onClick={clearAll}
            >
              {t('findings.filter.clearAll', 'Clear filters')}
            </Button>
          ) : null}
        </>
      }
      end={resultLabel ? <span role="status">{resultLabel}</span> : undefined}
    />
  )
}

/** The params a 400 INVALID_FILTER names (`details[].param`), if the error is one. */
export function invalidFilterParams(error: unknown): string[] | undefined {
  const e = error as { code?: unknown; details?: unknown } | undefined
  if (!e || e.code !== 'INVALID_FILTER') return undefined
  const details = Array.isArray(e.details) ? e.details : []
  const params = details
    .map((d) => (d as { param?: unknown })?.param)
    .filter((p): p is string => typeof p === 'string' && p !== '')
  return params
}

/**
 * The list refused a filter it does not know (a typo in a shared link). It
 * says which one and offers to remove it, instead of showing a failed load.
 */
export function InvalidFilterNotice({
  params,
  onRemove,
}: {
  params: string[]
  onRemove: (params: string[]) => void
}) {
  const { t } = useTranslation()
  const names = params.map((p) => `“${toDisplayText(p, 40)}”`).join(', ')
  return (
    <Alert variant="destructive" data-testid="invalid-filter-notice">
      <AlertCircle />
      <AlertTitle>
        {params.length === 0
          ? t('findings.filter.invalidUnnamed', 'A filter in this link is not valid')
          : params.length === 1
            ? t('findings.filter.invalidOne', 'This link has a filter we do not know: {names}', {
                names,
              })
            : t('findings.filter.invalidMany', 'This link has filters we do not know: {names}', {
                names,
              })}
      </AlertTitle>
      <AlertDescription>
        {params.length > 0 && (
          <Button variant="outline" size="sm" className="mt-2" onClick={() => onRemove(params)}>
            {t('findings.filter.removeIt', 'Remove it')}
          </Button>
        )}
      </AlertDescription>
    </Alert>
  )
}
