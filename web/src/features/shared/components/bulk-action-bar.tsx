'use client'

import { useEffect, type ReactNode } from 'react'
import { MoreHorizontal, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { DensityScope } from '@/components/ui/density'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useTranslation } from '@/context/i18n-provider'

/**
 * Actions for the rows selected in a list, as a bar floating at the bottom of
 * the viewport. It appears over the content instead of being inserted above
 * the table, so selecting a row never shifts the list. Escape clears the
 * selection.
 *
 * Anatomy: the count, an optional status ("Select all N that match" or "All N
 * that match are selected"), a divider, at most two direct actions, More
 * (the rest, as menu items) and X. Every control is one height: the kit's
 * dense size (28 on a desktop).
 */
export function BulkActionBar({
  count,
  onClear,
  children,
  noun,
  status,
  more,
}: {
  count: number
  onClear: () => void
  /** At most two direct actions. */
  children: ReactNode
  /** Text after the count, e.g. "findings selected". */
  noun?: string
  /** Beside the count: the select-all-matching offer or its state. */
  status?: ReactNode
  /** The other actions, as `DropdownMenuItem`s under More. */
  more?: ReactNode
}) {
  const { t } = useTranslation()
  useEffect(() => {
    if (count === 0) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !e.defaultPrevented) onClear()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [count, onClear])

  if (count === 0) return null
  return (
    <div className="pointer-events-none fixed inset-x-0 bottom-6 z-40 flex justify-center px-4">
      <div
        role="toolbar"
        aria-label={t('common.bulkBar.label', 'Actions for selected rows')}
        className="pointer-events-auto flex max-w-full animate-in items-center gap-1.5 overflow-x-auto rounded-xl border bg-popover p-1.5 ps-4 text-popover-foreground shadow-lg duration-200 fade-in-0 slide-in-from-bottom-2"
      >
        <span className="whitespace-nowrap text-sm font-medium tabular-nums">
          {count}{' '}
          {noun ? (
            // A phone shows the short word only, so X stays on screen; screen
            // readers hear the page's noun at every width.
            <>
              <span className="sr-only sm:not-sr-only">{noun}</span>
              <span aria-hidden="true" className="sm:hidden">
                {t('common.bulkBar.selected', 'selected')}
              </span>
            </>
          ) : (
            t('common.bulkBar.selected', 'selected')
          )}
        </span>
        {/* The bulk bar is a dense place: its controls take the kit's dense size. */}
        <DensityScope>
          {status}
          <span aria-hidden className="mx-1.5 h-5 w-px shrink-0 bg-border" />
          {children}
          {more && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  className="shrink-0"
                  aria-label={t('common.bulkBar.more', 'More actions')}
                >
                  <MoreHorizontal className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent side="top" align="end">
                {more}
              </DropdownMenuContent>
            </DropdownMenu>
          )}
          <Button
            variant="ghost"
            size="icon-sm"
            className="shrink-0"
            onClick={onClear}
            aria-label={t('common.bulkBar.clear', 'Clear selection')}
            title={t('common.bulkBar.clearHint', 'Clear selection (Esc)')}
          >
            <X className="h-4 w-4" />
          </Button>
        </DensityScope>
      </div>
    </div>
  )
}
