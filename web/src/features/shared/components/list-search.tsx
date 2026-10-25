'use client'

import * as React from 'react'
import { Search, X } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

/**
 * The one search box of a list (research/267). Every list toolbar draws its
 * search with this, so the field looks and behaves the same on every page:
 *
 * - 36px high, the search icon at the start, the placeholder "Search <fields>…"
 *   naming what is matched, an accessible name of its own;
 * - a clear button while there is text; Escape clears it too;
 * - `/` anywhere on the page (outside a text field) focuses it (`ListToolbar`
 *   routes the key to the first toolbar on the page);
 * - when the list has a filter panel, its trigger is passed as `filter` and is
 *   joined to the start of the field: one control, never split by a wrap.
 *
 * The component only reports what was typed. A server-side search passes the
 * value through `useSearchQuery` / `useListParams` before it reaches a request
 * (300 ms debounce, minimum length, IME composition); see
 * `hooks/__tests__/search-query-guard.test.ts`.
 */
export interface ListSearchProps {
  value: string
  onChange: (value: string) => void
  /** "Search <fields>…", naming what the search matches. */
  placeholder: string
  /** Accessible name, e.g. "Search findings". Defaults to the placeholder. */
  label?: string
  /** The list's filter trigger (`FilterButton` / `FilterPanelToggle`), joined to the field's start. */
  filter?: React.ReactNode
  className?: string
  /** Extra props for the input (e.g. `data-testid`, `onKeyDown`). */
  inputProps?: Omit<
    React.ComponentProps<typeof Input>,
    'value' | 'onChange' | 'placeholder' | 'className' | 'type'
  >
}

export function ListSearch({
  value,
  onChange,
  placeholder,
  label,
  filter,
  className,
  inputProps,
}: ListSearchProps) {
  const { t } = useTranslation()
  const inputRef = React.useRef<HTMLInputElement>(null)
  const { onKeyDown, ...restInput } = inputProps ?? {}

  return (
    <div
      data-slot="list-search"
      className={cn(
        // Grows into the start group's free width, never below 12rem and never
        // wider than 28rem, so the field sits at the same place and size on
        // every list and the end group keeps its room.
        'flex min-w-48 flex-[1_1_16rem] items-center sm:max-w-md',
        filter &&
          '[&_[data-slot=filter-button]]:z-10 [&_[data-slot=filter-button]]:rounded-e-none',
        className
      )}
    >
      {filter}
      <div className={cn('relative min-w-0 flex-1', filter && '-ms-px')}>
        <Search
          aria-hidden="true"
          className="pointer-events-none absolute start-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
        />
        <Input
          ref={inputRef}
          type="search"
          data-slot="list-search-input"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape' && value) {
              e.preventDefault()
              e.stopPropagation()
              onChange('')
            }
            onKeyDown?.(e)
          }}
          placeholder={placeholder}
          aria-label={label ?? placeholder}
          aria-keyshortcuts="/"
          className={cn(
            // The native clear control is replaced by ours (one look in every browser).
            'h-9 ps-9 pe-9 focus-visible:z-20 [&::-webkit-search-cancel-button]:appearance-none',
            filter && 'rounded-s-none'
          )}
          {...restInput}
        />
        {value ? (
          <button
            type="button"
            data-slot="list-search-clear"
            aria-label={t('common.listSearch.clear', 'Clear search')}
            onClick={() => {
              onChange('')
              inputRef.current?.focus()
            }}
            className="absolute end-1.5 top-1/2 z-30 flex size-6 -translate-y-1/2 items-center justify-center rounded-sm text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          >
            <X className="size-3.5" aria-hidden="true" />
          </button>
        ) : null}
      </div>
    </div>
  )
}
