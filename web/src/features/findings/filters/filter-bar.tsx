'use client'

import { useEffect, useMemo, useRef, type ReactElement, type ReactNode } from 'react'
import { AlertCircle, X } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { FilterChipsRow } from '@/features/shared/components/filter-chips-row'
import { useTranslation } from '@/context/i18n-provider'
import { toDisplayText } from '@/lib/untrusted-text'
import { FilterChip, type FilterChipEdit } from './filter-chip'
import { AdvancedChip, FQ_PARAM } from './filter-query-mode'
import {
  paramFor,
  readFilters,
  viewFilters,
  withFilterReplaced,
  withoutParam,
  type FieldContract,
  type FilterContract,
} from './model'

interface FilterBarProps {
  /** The page URL's query. */
  search: URLSearchParams
  /** The contract to read chips with (the loaded one plus the page-owned fields). */
  contract: FilterContract
  /** Params something else draws (the context chips). */
  skip: ReadonlySet<string>
  /** The open saved view's filter: its chips are locked. */
  viewFilter?: Record<string, unknown>
  /** The context chips (an asset, a scan...), drawn first. */
  leading?: ReactNode
  /** Navigate to a new query (the page replaces the URL). */
  onSearchChange: (next: URLSearchParams) => void
  /**
   * The search field is in Query mode: the text owns the filter, so the
   * chips, Add filter and Clear step aside (the context chips stay). An open
   * view's conditions are in the text too.
   */
  queryActive?: boolean
  /** Open the search field's Query mode (the Advanced chip's text). */
  onOpenQuery?: () => void
  /**
   * Lets a chip's text open its filter's editor (operator and values): the
   * loaded contract, and a signal to load it while an editor is open. Chips
   * of the open saved view and unknown filters are never editable.
   */
  edit?: Omit<FilterChipEdit, 'onApply'>
}

/**
 * Every active filter as a chip (Add filter sits on the toolbar row, see
 * `AddFilterPopover`). Chips from the open saved
 * view come first and are locked; a param no registry field knows is shown as
 * an unknown filter to remove, never silently ignored.
 */
export function FilterBar({
  search,
  contract,
  skip,
  viewFilter,
  leading,
  onSearchChange,
  queryActive,
  onOpenQuery,
  edit,
}: FilterBarProps) {
  const { t } = useTranslation()
  const fq = search.get(FQ_PARAM)

  // An edited filter may move to another param ("is" to "is not"), which
  // draws a new chip: focus goes to that chip's text once the URL has it.
  const focusParam = useRef<string | null>(null)
  useEffect(() => {
    const param = focusParam.current
    if (!param || !search.has(param)) return
    focusParam.current = null
    if (!/^[\w.-]+$/.test(param)) return
    document
      .querySelector<HTMLElement>(`[data-slot="filter-chip-edit"][data-filter-param="${param}"]`)
      ?.focus()
  }, [search])
  const chipEdit: FilterChipEdit | undefined = edit && {
    ...edit,
    onApply: (filter, field, op, values) => {
      focusParam.current = paramFor(field, op) ?? null
      onSearchChange(withFilterReplaced(search, filter.param, field, op, values))
    },
  }
  const fieldOf = (name: string): FieldContract | undefined =>
    contract.fields.find((f) => f.name === name)

  const { filters, unknown } = useMemo(
    () => readFilters(search, contract, skip),
    [search, contract, skip]
  )
  const fromView = useMemo(() => viewFilters(viewFilter, contract), [viewFilter, contract])

  // The open view's own conditions: locked. Conditions chips cannot show
  // (an OR, a group) are one chip that opens Query mode, where the field
  // holds the view's whole text.
  const viewChips: ReactElement[] = [
    ...(fromView.complex
      ? [
          <button
            key="view-complex"
            type="button"
            data-testid="filter-chip"
            data-slot="filter-chip-view-advanced"
            data-locked="true"
            title={t('findings.filter.viewConditions', 'Conditions from the saved view')}
            onClick={() => onOpenQuery?.()}
            className="inline-flex items-center rounded-full border bg-muted/50 px-2 py-0.5 text-xs hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          >
            {t('findings.filter.viewAdvanced', 'Advanced filter')}
          </button>,
        ]
      : []),
    ...fromView.filters.flatMap((f) => {
      const field = fieldOf(f.field)
      return field ? [<FilterChip key={`view-${f.param}`} filter={f} field={field} />] : []
    }),
  ]
  const chips: ReactElement[] = [
    ...(fq
      ? [
          <AdvancedChip
            key="advanced"
            text={fq}
            onOpen={() => onOpenQuery?.()}
            onRemove={() => onSearchChange(withoutParam(search, FQ_PARAM))}
          />,
        ]
      : []),
    ...viewChips,
    ...filters.flatMap((f) => {
      const field = fieldOf(f.field)
      return field
        ? [
            <FilterChip
              key={f.param}
              filter={f}
              field={field}
              edit={chipEdit}
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
    if (fq) next = withoutParam(next, FQ_PARAM)
    onSearchChange(next)
  }

  if (queryActive) {
    // The text is the whole filter, an open view's own conditions included
    // (the field prints them): no chip repeats it.
    return leading ? (
      <FilterChipsRow data-testid="findings-filter-bar" leading={leading} chips={[]} />
    ) : null
  }
  return (
    <FilterChipsRow
      data-testid="findings-filter-bar"
      leading={leading}
      chips={chips}
      // Going back to the view is the title row's Reset; the row ends with
      // Clear filters only.
      onClearAll={filters.length + unknown.length + (fq ? 1 : 0) > 1 ? clearAll : undefined}
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
