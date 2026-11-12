'use client'

/**
 * Grouped lists for the shared DataTable: one table, groups as full-width
 * header rows between the rows (the house standard, see "Grouped lists" in
 * docs/ui-style-contract.md). Two sources:
 *
 * - Client groups: the table groups the rows it has (`getKey`, `order`).
 * - Server groups: the page passes the group keys of the current page
 *   (`groups`, paginated by the server) and loads each group's rows on
 *   expand; `renderFooter` carries "Show N more".
 */

import { useTranslation } from '@/context/i18n-provider'
import * as React from 'react'
import type { Row, RowModel, Table as TanstackTable } from '@tanstack/react-table'
import { ChevronRight } from 'lucide-react'
import { Checkbox } from '@/components/ui/checkbox'
import { cn } from '@/lib/utils'

export interface DataTableRowGroups<TData> {
  /** The group a row belongs to. */
  getKey: (row: TData) => string
  /** Group order by key; keys not listed follow in order of appearance. */
  order?: string[]
  /**
   * The header's content (name, meta, counts). Client groups get every row of
   * the group, on all pages (a group can run past a page break); server
   * groups get the rows loaded so far.
   */
  renderHeader: (key: string, rows: TData[]) => React.ReactNode
  /**
   * Server groups: the groups of this page, in order. Every listed group gets
   * a header even before its rows are loaded; rows of unlisted groups are not
   * shown. Leave unset to group the table's own rows.
   */
  groups?: string[]
  /** Groups expand and collapse from a chevron in their header. */
  collapsible?: boolean
  /** Controlled expanded groups (with `collapsible`). */
  expandedKeys?: string[]
  onExpandedKeysChange?: (keys: string[]) => void
  /** Uncontrolled: whether groups start expanded. Default true. */
  defaultExpanded?: boolean
  /**
   * A checkbox in the header selects the group's rows on screen. Needs the
   * table's `select` column; off by default.
   */
  selectable?: boolean
  /**
   * Group status (counts, progress) between the name and the actions. It
   * wraps onto its own line when the header is too narrow for one line.
   */
  renderSummary?: (key: string, rows: TData[]) => React.ReactNode
  /**
   * Group actions at the end of the header (e.g. View, Mark fixed, Approve),
   * in their own slot: they never shrink and never overlap the name or the
   * summary; on a narrow header they move to the next line, end-aligned.
   */
  renderActions?: (key: string, rows: TData[]) => React.ReactNode
  /** A row after an expanded group's rows, e.g. "Show 20 more". */
  renderFooter?: (key: string, rows: TData[]) => React.ReactNode
  /** The group's rows are loading: skeleton rows stand in while it has none. */
  isGroupLoading?: (key: string) => boolean
  /** Plain-text group name for the expand button and checkbox labels. */
  getLabel?: (key: string) => string
}

/**
 * Rows partitioned by group (stable within a group), in group order.
 * Exported for tests.
 */
export function groupRowsForDisplay<R>(
  rows: R[],
  getKey: (row: R) => string,
  order: string[] = []
): { key: string; rows: R[] }[] {
  const groups = new Map<string, R[]>()
  for (const row of rows) {
    const k = getKey(row)
    const list = groups.get(k)
    if (list) list.push(row)
    else groups.set(k, [row])
  }
  const rank = new Map(order.map((k, i) => [k, i]))
  const seen = [...groups.keys()]
  const appearance = new Map(seen.map((k, i) => [k, i]))
  seen.sort((a, b) => {
    const ra = rank.get(a) ?? Number.MAX_SAFE_INTEGER
    const rb = rank.get(b) ?? Number.MAX_SAFE_INTEGER
    if (ra !== rb) return ra - rb
    return (appearance.get(a) ?? 0) - (appearance.get(b) ?? 0)
  })
  return seen.map((key) => ({ key, rows: groups.get(key) ?? [] }))
}

/**
 * Server groups: every listed group in order, with the rows that belong to
 * it. Exported for tests.
 */
export function rowsForServerGroups<R>(
  rows: R[],
  getKey: (row: R) => string,
  groups: string[]
): { key: string; rows: R[] }[] {
  const byKey = new Map<string, R[]>(groups.map((k) => [k, []]))
  for (const row of rows) byKey.get(getKey(row))?.push(row)
  return groups.map((key) => ({ key, rows: byKey.get(key) ?? [] }))
}

/**
 * Wraps tanstack's sorted row model so rows come out group by group before
 * pagination slices them. Without it a client-paginated grouped table shows
 * a group on several pages, each with a header that counts only that page.
 */
export function groupSortedRowModel<TData>(
  inner: (table: TanstackTable<TData>) => () => RowModel<TData>,
  getGroups: () => DataTableRowGroups<TData> | undefined
) {
  return (table: TanstackTable<TData>) => {
    const compute = inner(table)
    let lastIn: RowModel<TData> | undefined
    let lastGroups: DataTableRowGroups<TData> | undefined
    let lastOut: RowModel<TData> | undefined
    return () => {
      const model = compute()
      const rg = getGroups()
      if (!rg || rg.groups) return model
      if (model === lastIn && rg === lastGroups && lastOut) return lastOut
      const rows = groupRowsForDisplay(model.rows, (r) => rg.getKey(r.original), rg.order).flatMap(
        (g) => g.rows
      )
      lastIn = model
      lastGroups = rg
      lastOut = { ...model, rows }
      return lastOut
    }
  }
}

/** Expanded-group state: controlled through the props, else kept here. */
export function useGroupExpansion<TData>(rowGroups: DataTableRowGroups<TData> | undefined) {
  // Uncontrolled: remember the groups that differ from the default, so groups
  // that appear later follow the default.
  const [toggled, setToggled] = React.useState<Set<string>>(() => new Set())
  const controlled = rowGroups?.expandedKeys
  const defaultExpanded = rowGroups?.defaultExpanded ?? true
  const isExpanded = React.useCallback(
    (key: string) => {
      if (!rowGroups?.collapsible) return true
      if (controlled) return controlled.includes(key)
      return toggled.has(key) ? !defaultExpanded : defaultExpanded
    },
    [rowGroups?.collapsible, controlled, toggled, defaultExpanded]
  )
  const toggle = React.useCallback(
    (key: string) => {
      if (controlled) {
        const next = controlled.includes(key)
          ? controlled.filter((k) => k !== key)
          : [...controlled, key]
        rowGroups?.onExpandedKeysChange?.(next)
        return
      }
      setToggled((prev) => {
        const next = new Set(prev)
        if (next.has(key)) next.delete(key)
        else next.add(key)
        return next
      })
    },
    [controlled, rowGroups]
  )
  return { isExpanded, toggle }
}

interface GroupHeaderProps<TData> {
  rowGroups: DataTableRowGroups<TData>
  groupKey: string
  rows: Row<TData>[]
  /** Rows handed to renderHeader / renderActions (the whole group). */
  groupRows?: TData[]
  expanded: boolean
  onToggle: () => void
  /** The table has a `select` column, so the group can select its rows. */
  canSelect: boolean
  /** id of the element holding the group's rows, for aria-controls. */
  controlsId: string
  headerId: string
}

/**
 * The content of a group header, one wrapping line of three slots:
 *
 * - identity: chevron, group checkbox and the page's content (name, facts);
 * - summary: the group's status (`renderSummary`), wraps under the identity
 *   when they do not fit side by side;
 * - actions: `renderActions`, never shrunk, aligned to the end.
 *
 * Nothing is positioned over the table: when the header is narrower than its
 * slots, slots move to the next line instead of overflowing the frame (an
 * overflowing header widened the table and slid its buttons under the
 * pinned row-actions column). A header with none of the controls renders the
 * page's content as it is.
 */
export function GroupHeaderContent<TData>({
  rowGroups,
  groupKey,
  rows,
  groupRows,
  expanded,
  onToggle,
  canSelect,
  controlsId,
  headerId,
}: GroupHeaderProps<TData>) {
  const { t } = useTranslation()
  const originals = groupRows ?? rows.map((r) => r.original)
  const content = rowGroups.renderHeader(groupKey, originals)
  const summary = rowGroups.renderSummary?.(groupKey, originals)
  const actions = rowGroups.renderActions?.(groupKey, originals)
  const selectable = canSelect && !!rowGroups.selectable
  const label = rowGroups.getLabel?.(groupKey) ?? groupKey
  if (!rowGroups.collapsible && !selectable && !actions && !summary) {
    return <div id={headerId}>{content}</div>
  }
  const selected = rows.filter((r) => r.getIsSelected()).length
  const checked = rows.length > 0 && selected === rows.length
  return (
    <div
      data-slot="row-group-header-content"
      className="flex min-h-7 min-w-0 flex-wrap items-center gap-x-4 gap-y-1.5"
    >
      <div
        data-slot="row-group-identity"
        className="flex min-w-0 flex-[1_1_18rem] items-center gap-2"
      >
        {rowGroups.collapsible && (
          <button
            type="button"
            onClick={onToggle}
            aria-expanded={expanded}
            aria-controls={controlsId}
            aria-label={
              expanded
                ? t('common.table.collapseGroup', 'Collapse {label}', { label })
                : t('common.table.expandGroup', 'Expand {label}', { label })
            }
            className="-ms-1 inline-flex size-6 shrink-0 items-center justify-center rounded-sm text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            <ChevronRight
              className={cn(
                'size-4 transition-transform motion-reduce:transition-none rtl:rotate-180',
                expanded && 'rotate-90 rtl:rotate-90'
              )}
            />
          </button>
        )}
        {selectable && (
          <Checkbox
            checked={checked || (selected > 0 && 'indeterminate')}
            disabled={rows.length === 0}
            onCheckedChange={(value) => {
              for (const r of rows) r.toggleSelected(!!value)
            }}
            aria-label={`Select the ${rows.length} rows of ${label}`}
          />
        )}
        <div id={headerId} className="min-w-0 flex-1">
          {content}
        </div>
      </div>
      {summary && (
        <div
          data-slot="row-group-summary"
          className="flex min-w-0 max-w-full flex-wrap items-center gap-x-3 gap-y-1"
        >
          {summary}
        </div>
      )}
      {actions && (
        <div
          data-slot="row-group-actions"
          className="ms-auto flex max-w-full shrink-0 flex-wrap items-center justify-end gap-1.5"
        >
          {actions}
        </div>
      )}
    </div>
  )
}
