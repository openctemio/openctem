'use client'

import * as React from 'react'
import { ChevronDown, X } from 'lucide-react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

/**
 * The list-state model (research/249 R21, amended): the state or status of a
 * list's rows is a filter, never a second tab row or a segmented control. On
 * a list without the Add-filter registry it is this control at the start of
 * the list toolbar: a filter token that reads "Status: Pending", opens a menu
 * of every value with its count, keeps its value in the URL (the page passes
 * `useUrlFilter`), and can be cleared back to all rows.
 *
 * A segmented control is only for the view mode of the same rows (table,
 * board, analytics) at the end of the toolbar.
 */
export interface FilterSelectOption<V extends string> {
  value: V
  label: string
  /** Rows with this value, in the viewer's scope; undefined while loading. */
  count?: number
}

export interface FilterSelectProps<V extends string> {
  /** What is filtered ("Status"); the token reads "Status: Pending". */
  label: string
  /** The current value; `allValue` (default '') means no filter. */
  value: V | ''
  options: FilterSelectOption<V>[]
  onChange: (value: V | '') => void
  /** The value that means every row. Default ''. */
  allValue?: V | ''
  /** Count of every row, shown beside "All" in the menu. */
  allCount?: number
  /** Label of the no-filter entry. Default "All". */
  allLabel?: string
  /**
   * false: one value is always chosen (the rows are of different kinds, e.g.
   * "Show: Origins"); no "All" entry and no clear button. Default true.
   */
  clearable?: boolean
  className?: string
}

export function FilterSelect<V extends string>({
  label,
  value,
  options,
  onChange,
  allValue = '',
  allCount,
  allLabel,
  clearable = true,
  className,
}: FilterSelectProps<V>) {
  const { t, locale } = useTranslation()
  const all = allLabel ?? t('common.filter.all', 'All')
  const current = options.find((o) => o.value === value)
  const filtered = clearable && value !== allValue && Boolean(current)
  const fmt = React.useMemo(() => new Intl.NumberFormat(locale), [locale])
  const count = (n?: number) =>
    typeof n === 'number' ? (
      <span className="ms-auto ps-4 tabular-nums text-muted-foreground">{fmt.format(n)}</span>
    ) : null

  return (
    <div
      data-slot="filter-select"
      data-filtered={filtered ? 'true' : 'false'}
      className={cn(
        'inline-flex h-9 max-w-full items-center rounded-md border bg-background text-sm',
        filtered && 'bg-muted/50',
        className
      )}
    >
      <DropdownMenu>
        <DropdownMenuTrigger
          className="inline-flex h-full min-w-0 cursor-pointer items-center gap-1.5 rounded-md ps-3 pe-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          aria-label={`${label}: ${current?.label ?? all}`}
        >
          <span className="text-muted-foreground">{label}:</span>
          <span className="truncate font-medium">{current?.label ?? all}</span>
          <ChevronDown aria-hidden className="size-4 shrink-0 text-muted-foreground" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="min-w-48">
          <DropdownMenuRadioGroup
            value={clearable ? (filtered ? value : allValue) : value}
            onValueChange={(v) => onChange(v as V | '')}
          >
            {clearable && (
              <DropdownMenuRadioItem value={allValue}>
                {all}
                {count(allCount)}
              </DropdownMenuRadioItem>
            )}
            {options.map((o) => (
              <DropdownMenuRadioItem key={o.value} value={o.value}>
                {o.label}
                {count(o.count)}
              </DropdownMenuRadioItem>
            ))}
          </DropdownMenuRadioGroup>
        </DropdownMenuContent>
      </DropdownMenu>
      {filtered && (
        <button
          type="button"
          onClick={() => onChange(allValue)}
          aria-label={t('common.filter.clearNamed', 'Clear {name}', { name: label })}
          className="me-1 inline-flex size-7 cursor-pointer items-center justify-center rounded-sm text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <X aria-hidden className="size-4" />
        </button>
      )}
    </div>
  )
}
