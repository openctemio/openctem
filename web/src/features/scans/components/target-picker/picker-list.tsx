'use client'

/**
 * The list frame shared by the target picker's sources (asset groups, scope
 * entries): a search box, a bordered scrolling list of checkbox rows with a
 * loading and an empty state, an optional "pick all" action above the list
 * and a footer note. Searching is the caller's (debounced through
 * useSearchQuery); this only lays it out.
 */

import type { ReactNode } from 'react'
import { Search } from 'lucide-react'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

export interface PickerRow {
  id: string
  label: string
  picked: boolean
  /** Not pickable; `description` says why. */
  disabled?: boolean
  /** One line under the label. */
  description?: ReactNode
  /** Right-aligned (a count, a badge). */
  trailing?: ReactNode
  /** The label is a target (mono). */
  mono?: boolean
}

interface PickerListProps {
  search: string
  onSearch: (value: string) => void
  searchPlaceholder: string
  searchLabel: string
  /** The list's accessible name. */
  listLabel: string
  rows: readonly PickerRow[]
  loading: boolean
  /** Shown when there are no rows. */
  emptyText: string
  onToggle: (row: PickerRow, picked: boolean) => void
  /** Above the list, e.g. "Add all in-scope entries". */
  actions?: ReactNode
  footer?: ReactNode
}

export function PickerList({
  search,
  onSearch,
  searchPlaceholder,
  searchLabel,
  listLabel,
  rows,
  loading,
  emptyText,
  onToggle,
  actions,
  footer,
}: PickerListProps) {
  return (
    <div className="space-y-3">
      <div className="relative">
        <Search
          className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-muted-foreground"
          aria-hidden
        />
        <Input
          placeholder={searchPlaceholder}
          aria-label={searchLabel}
          value={search}
          onChange={(e) => onSearch(e.target.value)}
          className="ps-10"
        />
      </div>
      {actions}
      <div
        className="max-h-72 overflow-y-auto rounded-md border"
        role="group"
        aria-label={listLabel}
      >
        {loading ? (
          <div className="space-y-2 p-2">
            {[0, 1, 2].map((i) => (
              <Skeleton key={i} className="h-8 w-full" />
            ))}
          </div>
        ) : rows.length === 0 ? (
          <p className="p-4 text-center text-sm text-muted-foreground">{emptyText}</p>
        ) : (
          <ul className="divide-y">
            {rows.map((row) => (
              <li key={row.id}>
                <label
                  className={cn(
                    'flex min-h-11 items-center gap-3 px-3 py-2',
                    row.disabled
                      ? 'cursor-not-allowed opacity-60'
                      : 'cursor-pointer hover:bg-muted/50',
                    row.picked && 'bg-primary/5'
                  )}
                >
                  <Checkbox
                    checked={row.picked}
                    disabled={row.disabled}
                    onCheckedChange={(c) => onToggle(row, c === true)}
                    aria-label={row.label}
                  />
                  <span className="min-w-0 flex-1">
                    <span
                      className={cn('block truncate text-sm', row.mono && 'font-mono')}
                      title={row.label}
                    >
                      {row.label}
                    </span>
                    {row.description && (
                      <span className="block truncate text-xs text-muted-foreground">
                        {row.description}
                      </span>
                    )}
                  </span>
                  {row.trailing}
                </label>
              </li>
            ))}
          </ul>
        )}
      </div>
      {footer}
    </div>
  )
}
