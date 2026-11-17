'use client'

/**
 * Row selection of the shared table: the checkbox column the table adds when
 * the page passes `bulk`, Shift-click and Shift+x ranges, `x` on the focused
 * row, and the selection the bulk bar acts on (rows on this page, or every
 * row the list's filter selects).
 */

import * as React from 'react'
import type { ColumnDef, Row, Table as TanstackTable } from '@tanstack/react-table'
import type { ActionMenuEntry } from '@/components/ui/action-menu'
import { Checkbox } from '@/components/ui/checkbox'

/**
 * What a bulk action acts on: the checked rows of this page, or every row the
 * list's filter selects ("Select all N that match"). A filter selection is
 * applied by the server, which re-applies the tenant, the caller's data scope
 * and permissions, so it never reaches a row the caller could not list.
 */
export type DataTableSelection<TData> =
  { kind: 'ids'; rows: TData[] } | { kind: 'filter'; total: number }

/** The `bulk` prop: a page that can act on several rows at once. */
export interface DataTableBulk<TData> {
  /** The row's name in its checkbox label ("Select {name}"). */
  rowLabel: (row: TData) => string
  /**
   * The whole checkbox label, when the page words it itself (e.g. "Select
   * finding {title}", the same label its phone cards use). Wins over rowLabel.
   */
  checkboxLabel?: (row: TData) => string
  /**
   * At most two direct actions (ghost `sm` buttons or one menu such as "Set
   * status"); the rest go in `more`.
   */
  actions: React.ReactNode
  /** The bar's More menu: items of the shared `ActionMenu`. */
  more?: ActionMenuEntry[]
  /**
   * Offer "Select all N that match" once the whole page is checked and the
   * list has more rows than the page. Pass it only where the page can apply
   * its actions by filter on the server. `max`: the server's limit for one
   * change by filter; above it the offer is disabled and says so.
   */
  matching?: { total: number; max?: number }
  /** The selection whenever it changes; `null` when nothing is selected. */
  onSelectionChange?: (selection: DataTableSelection<TData> | null) => void
  /** Text after the count in the bar, e.g. "findings selected". */
  noun?: string
}

/** Where a `x` press or a checkbox click must not toggle a row. */
const TYPING_SELECTOR =
  'input, textarea, select, [contenteditable=""], [contenteditable="true"], [role="textbox"], [role="combobox"]'

/** The checkbox column the table adds for `bulk`: pinned first, 40 px. */
export function bulkSelectColumn<TData>(labels: {
  allOnPage: string
  row: (row: TData) => string
}): ColumnDef<TData, unknown> {
  return {
    id: 'select',
    meta: { kind: 'select', label: labels.allOnPage },
    header: ({ table }) => (
      <Checkbox
        checked={
          table.getIsAllPageRowsSelected() || (table.getIsSomePageRowsSelected() && 'indeterminate')
        }
        onCheckedChange={(value) => table.toggleAllPageRowsSelected(!!value)}
        // Nothing to select on an empty list (a first run, a no-match).
        disabled={table.getRowModel().rows.length === 0}
        aria-label={labels.allOnPage}
      />
    ),
    cell: ({ row }) => (
      <Checkbox
        checked={row.getIsSelected()}
        disabled={!row.getCanSelect()}
        onCheckedChange={(value) => row.toggleSelected(!!value)}
        aria-label={labels.row(row.original)}
        onClick={(e) => e.stopPropagation()}
      />
    ),
    enableSorting: false,
    enableHiding: false,
  }
}

/**
 * Shift ranges and the `x` key. The anchor is the row toggled last (by a
 * click on its checkbox or by `x`); Shift-click or Shift+x sets every row
 * between the anchor and this one to this row's new state. Works for the
 * table's own checkbox column and for a page's own `select` column.
 */
export function useRangeSelection<TData>(table: TanstackTable<TData>, enabled: boolean) {
  const anchor = React.useRef<string | null>(null)

  const toggleRange = React.useCallback(
    (row: Row<TData>) => {
      const rows = table.getRowModel().rows
      const from = anchor.current ? rows.findIndex((r) => r.id === anchor.current) : -1
      const to = rows.findIndex((r) => r.id === row.id)
      anchor.current = row.id
      if (from < 0 || to < 0) {
        row.toggleSelected()
        return
      }
      const select = !row.getIsSelected()
      const [a, b] = from < to ? [from, to] : [to, from]
      table.setRowSelection((prev) => {
        const next = { ...prev }
        for (const r of rows.slice(a, b + 1)) {
          if (!r.getCanSelect()) continue
          if (select) next[r.id] = true
          else delete next[r.id]
        }
        return next
      })
    },
    [table]
  )

  /** Capture handler for the select cell: Shift-click selects a range. */
  const onSelectCellClickCapture = React.useCallback(
    (e: React.MouseEvent, row: Row<TData>) => {
      if (!enabled) return
      if (!(e.target as HTMLElement).closest('[role="checkbox"]')) return
      if (e.shiftKey && anchor.current && anchor.current !== row.id) {
        // The checkbox's own toggle must not run as well.
        e.preventDefault()
        e.stopPropagation()
        toggleRange(row)
        return
      }
      anchor.current = row.id
    },
    [enabled, toggleRange]
  )

  /** Key handler for the table body: `x` toggles the focused row, Shift+x a range. */
  const onBodyKeyDown = React.useCallback(
    (e: React.KeyboardEvent) => {
      if (!enabled || e.key.toLowerCase() !== 'x') return
      if (e.ctrlKey || e.metaKey || e.altKey || e.defaultPrevented) return
      const target = e.target as HTMLElement
      if (target.closest(TYPING_SELECTOR)) return
      const id = target.closest<HTMLElement>('tr[data-row-id]')?.dataset.rowId
      const row = id ? table.getRowModel().rowsById[id] : undefined
      if (!row || !row.getCanSelect()) return
      e.preventDefault()
      if (e.shiftKey && anchor.current && anchor.current !== row.id) {
        toggleRange(row)
        return
      }
      anchor.current = row.id
      row.toggleSelected()
    },
    [enabled, table, toggleRange]
  )

  return { onSelectCellClickCapture, onBodyKeyDown }
}
