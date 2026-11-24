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
import { ToolbarSlot } from './toolbar-slot'

/**
 * The list-state model (research/249 R21, amended): the state or status of a
 * list's rows is a filter, never a second tab row or a segmented control. On
 * a list without the Add-filter registry it is this control at the start of
 * the list toolbar: a filter token that reads "Status: Pending", opens a menu
 * of every value with its count, keeps its value in the URL (the page passes
 * `useUrlFilter`), and can be cleared back to all rows.
 *
 * A list's fixed scopes (Findings: Practice, State) are base chips: this
 * control with `clearable={false}` and `foldLabel`, first after the search.
 * They are never removed; on a narrow toolbar the key ("Practice:") folds away
 * and stays in the accessible name.
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
  /**
   * Hide the key ("Practice:") when the toolbar is narrow (under 56rem), so a
   * base chip reads just its value there. The key stays in the accessible name.
   * A clearable select with no value chosen reads its key there ("State")
   * instead of "All", so two selects on one list never both read "All".
   */
  foldLabel?: boolean
  /**
   * Every value label the control can ever show (default: the options, and
   * "All" when clearable). The value sits in a box as wide as the longest, so
   * choosing a value, or options arriving later, never changes the control's
   * width. Pass the whole set when `options` lists only some of it.
   */
  sizeLabels?: readonly string[]
  /** The menu opened or closed: lets a page read what only the menu shows when it opens. */
  onOpenChange?: (open: boolean) => void
  className?: string
}

/** Hidden while the toolbar is narrow (under 56rem) or folds its labels. */
const FOLD_HIDDEN = '@max-4xl/toolbar:hidden group-data-[fold=true]/toolbar:hidden'

/**
 * The trigger and the clear button span the whole token, its 1 px border
 * included: the box is the control height (36 px on a phone), so their hit
 * area is too, instead of the 34 px left inside the border. The clear button
 * is icon-only, so it is a square of that height (`aspect-square`); its room
 * is the same square.
 */
const FULL_BOX_HEIGHT = '-my-px h-[calc(100%+2px)]'

export function FilterSelect<V extends string>({
  label,
  value,
  options,
  onChange,
  allValue = '',
  allCount,
  allLabel,
  clearable = true,
  foldLabel = false,
  sizeLabels,
  onOpenChange,
  className,
}: FilterSelectProps<V>) {
  const { t, locale } = useTranslation()
  const all = allLabel ?? t('common.filter.all', 'All')
  const current = options.find((o) => o.value === value)
  const filtered = clearable && value !== allValue && Boolean(current)
  // Folded with nothing chosen: the key stands in for "All".
  const keyForAll = foldLabel && clearable
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
        'inline-flex h-control-field max-w-full items-center rounded-md border bg-background text-body max-md:h-control-touch max-md:text-dense',
        filtered && 'bg-muted/50',
        className
      )}
    >
      <DropdownMenu onOpenChange={onOpenChange}>
        <DropdownMenuTrigger
          className={cn(
            FULL_BOX_HEIGHT,
            'inline-flex min-w-0 cursor-pointer items-center gap-1.5 rounded-md ps-3 pe-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring'
          )}
          aria-label={`${label}: ${current?.label ?? all}`}
        >
          <span className={cn('text-muted-foreground', foldLabel && FOLD_HIDDEN)}>{label}:</span>
          {/* The value is whole wherever the row has room: the slot is as
              wide as the longest value (up to 15rem, so one very long name
              does not stretch the token for every other value) and only
              shrinks, ending in an ellipsis, when the row itself is too
              narrow. The full value stays in its title and the trigger's
              accessible name. */}
          <ToolbarSlot
            className="max-w-60 font-medium"
            options={[
              ...(sizeLabels ?? [...(clearable ? [all] : []), ...options.map((o) => o.label)]),
              // The key is one of the texts the slot shows: it sizes the slot
              // too, so folding and choosing a value move nothing.
              ...(keyForAll ? [label] : []),
            ]}
            title={current?.label ?? all}
          >
            {keyForAll && !filtered ? (
              <>
                <span className={FOLD_HIDDEN}>{all}</span>
                <span
                  data-slot="filter-select-key"
                  className="hidden @max-4xl/toolbar:inline group-data-[fold=true]/toolbar:inline"
                >
                  {label}
                </span>
              </>
            ) : (
              (current?.label ?? all)
            )}
          </ToolbarSlot>
          <ChevronDown aria-hidden className="size-4 shrink-0 text-muted-foreground" />
        </DropdownMenuTrigger>
        <DropdownMenuContent>
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
      {/* The clear button's room is kept while nothing is filtered, so
          choosing a value never changes the token's width. */}
      {filtered ? (
        <button
          type="button"
          data-slot="filter-select-clear"
          onClick={() => onChange(allValue)}
          aria-label={t('common.filter.clearNamed', 'Clear {name}', { name: label })}
          className={cn(
            FULL_BOX_HEIGHT,
            'group/clear me-1 inline-flex aspect-square shrink-0 cursor-pointer items-center justify-center focus-visible:outline-none'
          )}
        >
          {/* The look stays a 28 px square; the button is the full height. */}
          <span className="inline-flex size-7 items-center justify-center rounded-sm text-muted-foreground group-hover/clear:bg-accent group-hover/clear:text-foreground group-focus-visible/clear:ring-2 group-focus-visible/clear:ring-ring">
            <X aria-hidden className="size-4" />
          </span>
        </button>
      ) : clearable ? (
        <span
          aria-hidden
          data-slot="filter-select-clear-room"
          className={cn(FULL_BOX_HEIGHT, 'me-1 aspect-square shrink-0')}
        />
      ) : null}
    </div>
  )
}
