'use client'

import * as React from 'react'
import { cn } from '@/lib/utils'
import { useIsMobile } from '@/hooks/use-mobile'
import { useTranslation } from '@/context/i18n-provider'
import {
  ColumnDef,
  ColumnFiltersState,
  type Column,
  type Header,
  type Table as TanstackTable,
  type Row,
  SortingState,
  VisibilityState,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from '@tanstack/react-table'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Button } from '@/components/ui/button'
import { DENSE_ATTRS } from '@/components/ui/density'
import { ListToolbar } from '../list-toolbar'
import { ErrorState } from '../error-state'
import type { ListSearchProps } from '../list-search'
import type { FilterPanelToggleProps } from '../filter-button'
import { Skeleton } from '@/components/ui/skeleton'
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  SlidersHorizontal,
  Inbox,
  RefreshCw,
} from 'lucide-react'
import {
  GroupHeaderContent,
  groupRowsForDisplay,
  groupSortedRowModel,
  rowsForServerGroups,
  useGroupExpansion,
  type DataTableRowGroups,
} from './data-table-groups'
import { TABLE_DENSITIES, useTableDensity, type TableDensity } from './use-table-density'
import { ariaSort, columnLayout, type ColumnLayout } from './column-meta'
import { RelativeTime } from '../relative-time'
import { PAGE_TITLE_ID } from '../page-header'
import { TableRefreshBar } from './table-refresh-bar'
import { pageSizeChoices } from '@/lib/page-size-options'

export { groupRowsForDisplay, rowsForServerGroups, type DataTableRowGroups }

/** What a phone card needs to offer the row's selection checkbox. */
export interface MobileRowSelection {
  selectable: boolean
  selected: boolean
  onSelectedChange: (selected: boolean) => void
}

/** A server-side search box (`DataTable`'s `search`). */
export type DataTableSearch = Omit<ListSearchProps, 'filter' | 'className'>

interface DataTableProps<TData, TValue> {
  columns: ColumnDef<TData, TValue>[]
  data: TData[]
  searchKey?: string
  searchPlaceholder?: string
  /**
   * A server-side search: the box shows `value` and reports typing through
   * `onChange`; the page sends the term through `useListParams` /
   * `useSearchQuery`. Replaces the built-in search (which only filters the rows
   * already loaded). Never draw a search box in `toolbarStart`.
   */
  search?: DataTableSearch
  showColumnToggle?: boolean
  showPagination?: boolean
  showSearch?: boolean
  pageSize?: number
  pageSizeOptions?: number[]
  emptyMessage?: string
  emptyDescription?: string
  /**
   * What an empty list shows. Either one block for every empty case, or the
   * two kinds: `nothingYet` (the list has no records at all: say so and offer
   * the first action) and `noMatch` (a search or filter left no row; defaults
   * to "No results found" with a Clear filters action when `onClearFilters`
   * is given). Which one shows follows `isFiltered`.
   */
  emptyState?: React.ReactNode | DataTableEmptyStates
  /**
   * A search or filter is applied, so an empty list is "no match" rather than
   * "nothing yet". Defaults to the table's own search being non-empty.
   */
  isFiltered?: boolean
  /** Clears the page's search and filters (the default no-match action). */
  onClearFilters?: () => void
  /**
   * The accessible name of the table (a visually hidden caption). Without it
   * the table is named by the page title (the PageHeader h1); a page holding
   * several tables names each one.
   */
  caption?: string
  /**
   * When the rows on screen were read. Older than the list's freshness budget,
   * the footer says "Updated 12 min ago" with a refresh button (`onRefresh`):
   * never a silent old list.
   */
  staleAt?: Date
  onRefresh?: () => void
  /**
   * The total could not be counted (the count failed or timed out): the
   * footer shows the rows on screen without a total, "Could not count" with
   * Retry (`onRetryCount`), and no Last page.
   */
  countUnavailable?: boolean
  onRetryCount?: () => void
  /**
   * Shown in place of the rows when the read failed. The toolbar, filters and
   * chips stay; the error does not replace the page.
   */
  errorState?: React.ReactNode
  /**
   * The error of the read (SWR `error`). With no rows loaded the body shows the
   * shared ErrorState with a Retry (`onRetry`); rows already loaded stay.
   * A custom `errorState` wins.
   */
  error?: unknown
  onRetry?: () => void
  /** What failed to load, phrased into "Failed to load {title}". Defaults to "the list". */
  errorTitle?: string
  onRowClick?: (row: TData) => void
  /**
   * The tone of a row: 'dim' greys its text (a colour, never opacity) for rows
   * that are not the work of the moment, such as low-priority or closed ones.
   */
  rowTone?: (row: TData) => 'dim' | undefined
  /**
   * Notified whenever the row selection changes, with the selected row data.
   * The table owns selection state internally (via the `select` column's
   * checkboxes); this is the only way for a parent to observe it (e.g. to drive
   * a bulk-action bar). Optional — existing callers are unaffected.
   */
  onSelectionChange?: (selectedRows: TData[]) => void
  /**
   * Server-side (manual) pagination. When set, the table does NOT slice `data`
   * itself — the parent fetches one page at a time and drives navigation:
   *   - `data` holds only the current page's rows
   *   - `pageCount`/`rowCount` come from the server response (total pages/rows)
   *   - `pagination` is the controlled `{pageIndex, pageSize}` state
   *   - `onPaginationChange` fires when the user pages or changes page size
   * Omit it entirely and the table keeps its default client-side pagination
   * over the full `data` array — existing callers are unaffected.
   */
  manualPagination?: boolean
  pageCount?: number
  rowCount?: number
  /** The server stopped counting at `rowCount`: the footer says "10,000+" instead of the exact-looking number. */
  rowCountCapped?: boolean
  pagination?: { pageIndex: number; pageSize: number }
  onPaginationChange?: (pagination: { pageIndex: number; pageSize: number }) => void
  /**
   * Stable row identity. Required for correct selection under manual pagination
   * (index-keyed selection would mis-mark rows when the page's data swaps).
   */
  getRowId?: (row: TData) => string
  /**
   * Server-side sorting (with `manualPagination`): the controlled sort state and
   * its change handler — the parent maps it to its API's sort parameter. Under
   * manual pagination without these, columns are not sortable at all: sorting
   * only the rows on screen would be misleading, and a header that toggles an
   * arrow without reordering anything is a dead control.
   */
  sorting?: SortingState
  onSortingChange?: (sorting: SortingState) => void
  /**
   * The page's facet-filter panel: renders the shared Filters toggle first in
   * the toolbar. Pass this rather than drawing a filter button in `toolbarStart`.
   */
  filterToggle?: FilterPanelToggleProps
  /** A filter trigger that opens a sheet (`FilterButton`) on a list with no side panel. */
  filter?: React.ReactNode
  /**
   * Filter tokens after the search box: `FilterSelect`, at most two selects,
   * a lens. Never a search box (pass `search`).
   */
  toolbarStart?: React.ReactNode
  /** Rendered at the end of the toolbar, before the column toggle. */
  toolbarEnd?: React.ReactNode
  /**
   * A full-width row directly under the toolbar, for the active context-filter
   * chips. Kept out of the toolbar row so a chip never makes that row taller
   * and never moves the controls on its end. Pass it only when there is
   * something to show (no empty row is reserved).
   */
  toolbarBelow?: React.ReactNode
  /**
   * Keep the selection checkbox and the first data column (the row's name) —
   * and the trailing `actions` column — in view while the table scrolls
   * sideways, so a row can be identified and acted on at any scroll position.
   * On by default.
   */
  stickyFirstColumn?: boolean
  /**
   * Change this value to clear the table's row selection (the table owns the
   * checkbox state; clearing only a parent's copy left rows ticked, and the
   * next tick brought the stale selection back).
   */
  resetSelectionKey?: string | number
  /** Hide the "N of M selected" note, e.g. when a bulk-action bar shows it. */
  showSelectionCount?: boolean
  /**
   * Phone layout: below `md` each row renders through this as a stacked card
   * instead of the table — a many-column table squeezed to phone width leaves
   * only the pinned name readable. Pagination stays the same.
   *
   * The second argument is the row's selection: `selectable` is true when the
   * table has a selection column, so a card offers the same checkbox the
   * table row has.
   */
  mobileRow?: (row: TData, selection: MobileRowSelection) => React.ReactNode
  /**
   * Without `mobileRow`, rows still render as cards below `md`, built from the
   * columns (first column as title, the next few as fields). Set false to keep
   * the scrolling table on phones.
   */
  mobileCards?: boolean
  /**
   * The rows are being fetched. The body shows skeleton rows instead of the
   * empty message, while the toolbar stays mounted — a server-side search box
   * must not lose focus (or its text) because a keystroke started a refetch.
   * Rows already on screen stay visible; skeletons only replace an empty body.
   */
  isLoading?: boolean
  /**
   * Rows already on screen are being re-read (filter, sort or page change, a
   * background revalidation). Draws a thin indeterminate bar on the top edge
   * of the table frame, below the toolbar, without moving the layout. A first
   * load with no rows uses `isLoading` (skeletons) instead.
   */
  isRefreshing?: boolean
  /** Accessible name of the refresh bar; defaults to "Refreshing". */
  refreshingLabel?: string
  /**
   * Columns hidden until the user turns them on under Columns, e.g. metrics
   * that most rows do not report. Keyed by column id.
   */
  initialColumnVisibility?: VisibilityState
  /**
   * Controlled column visibility. With it the table shows exactly these
   * columns and reports every change through `onColumnVisibilityChange`
   * (a page that saves the columns with a view, or keeps them in the URL).
   * Without it the table keeps its own state, started from
   * `initialColumnVisibility`.
   */
  columnVisibility?: VisibilityState
  onColumnVisibilityChange?: (next: VisibilityState) => void
  /**
   * Controlled row density: shown as given, and every pick goes to
   * `onDensityChange` instead of the per-browser preference.
   */
  density?: TableDensity
  onDensityChange?: (next: TableDensity) => void
  /**
   * Grouped list: a full-width header row before each group's rows, in one
   * table (see "Grouped lists" in docs/ui-style-contract.md). Client groups
   * follow `order`, then first appearance, and a client-paginated table pages
   * through the rows group by group. Server groups (`groups`) render a header
   * for each listed group and paginate the groups themselves.
   */
  rowGroups?: DataTableRowGroups<TData>
  /** What the pagination counts ("Showing 1 - 20 of 57 groups"). Default "results". */
  paginationNoun?: string
  /** Label of the page-size select. Default "Rows per page". */
  pageSizeLabel?: string
  /**
   * Row density until the user picks one in the table's Display menu:
   * `compact` 32, `default` 40, `comfortable` 52 (a second line). The user's
   * choice is a per-user preference that every table follows.
   */
  defaultDensity?: TableDensity
  /**
   * Sticky column header with the two scroll modes (the table fits: the page
   * scrolls and the header sticks; wider than its frame: the frame scrolls on
   * both axes). Off by default until it is proven on every page; off, the
   * frame scrolls sideways as before.
   */
  stickyHeader?: boolean
}

/** The two kinds of empty list (`emptyState`). */
export interface DataTableEmptyStates {
  nothingYet: React.ReactNode
  noMatch?: React.ReactNode
}

function isEmptyStates(v: unknown): v is DataTableEmptyStates {
  return (
    typeof v === 'object' &&
    v !== null &&
    !React.isValidElement(v) &&
    !Array.isArray(v) &&
    'nothingYet' in v
  )
}

/** Text, number and date columns: where the content of a header and its cells sits. */
const ALIGN_CLASS: Record<ColumnLayout['align'], string | undefined> = {
  start: undefined,
  end: 'text-end',
  center: 'text-center',
}

/** Skeleton rows shown in an empty body while `isLoading`. */
const LOADING_ROWS = 5

/** Cell padding of compact rows (the row height itself is --row-h). */
const COMPACT_CELL_CLASS = 'py-0.5'

const DENSITY_LABEL_KEYS: Record<TableDensity, [string, string]> = {
  compact: ['common.table.densityCompact', 'Compact'],
  default: ['common.table.densityDefault', 'Default'],
  comfortable: ['common.table.densityComfortable', 'Comfortable'],
}

/**
 * Mode B (the table is wider than its frame): the frame scrolls on both axes,
 * at most the viewport under the app header less the toolbar and footer, and
 * never below 320 px.
 */
const SCROLL_FRAME_STYLE: React.CSSProperties = {
  maxHeight: 'max(20rem, calc(100dvh - var(--app-header-h) - 6rem))',
}

/** The narrowest a row's name column may get: other columns scroll instead. */
const NAME_COLUMN_FLOOR = 'min-w-[min(12rem,36vw)]'

/** Fixed width of the selection column, so the pinned column after it knows its offset. */
const SELECT_COL_WIDTH = 40

/**
 * Pinned cells must be opaque (content scrolls underneath), so they repeat the
 * row's state colours as solid equivalents over the page background: hover
 * (and a focused control in the row) 4% ink, selected 7% ink.
 */
const PINNED_CELL_CLASS =
  'sticky z-[1] bg-background group-hover/row:bg-[color-mix(in_srgb,var(--foreground)_4%,var(--background))] group-focus-within/row:bg-[color-mix(in_srgb,var(--foreground)_4%,var(--background))] group-data-[state=selected]/row:bg-[color-mix(in_srgb,var(--foreground)_7%,var(--background))]'

/** The header row sticks: at the top of the page's scroller (under the app header) or of the frame (Mode B). */
const STICKY_HEAD_CLASS = 'sticky z-[2] bg-background'
const STICKY_HEAD_PINNED_CLASS = 'z-[3]'

/** Soft edge after the start-pinned columns, shown while content is hidden under them. */
const PINNED_START_EDGE_CLASS =
  "after:pointer-events-none after:absolute after:inset-y-0 after:-end-3 after:w-3 after:bg-gradient-to-r after:from-foreground/10 after:to-transparent after:opacity-0 after:transition-opacity after:content-[''] rtl:after:bg-gradient-to-l group-data-[hidden-start=true]/table:after:opacity-100"

/** Soft edge before the end-pinned actions column, shown while content remains to scroll. */
const PINNED_END_EDGE_CLASS =
  "before:pointer-events-none before:absolute before:inset-y-0 before:-start-3 before:w-3 before:bg-gradient-to-l before:from-foreground/10 before:to-transparent before:opacity-0 before:transition-opacity before:content-[''] rtl:before:bg-gradient-to-r group-data-[hidden-end=true]/table:before:opacity-100"

/** Columns the automatic phone card treats as controls rather than fields. */
const CONTROL_COLUMN_IDS = new Set(['select', 'actions'])
/** Fields shown under the title on an automatic phone card. */
const MOBILE_CARD_FIELDS = 4

/**
 * A column's readable label for the phone card: `meta.label`, a string
 * header, or the `title` of a `DataTableColumnHeader` header; else its id.
 */
function columnLabel<TData>(header: Header<TData, unknown>): string {
  const def = header.column.columnDef
  const metaLabel = (def.meta as { label?: unknown } | undefined)?.label
  if (typeof metaLabel === 'string') return metaLabel
  if (typeof def.header === 'string') return def.header
  if (typeof def.header === 'function') {
    try {
      const el = def.header(header.getContext())
      if (React.isValidElement<{ title?: unknown }>(el) && typeof el.props.title === 'string') {
        return el.props.title
      }
    } catch {
      // A header that needs React context cannot be read here; fall through.
    }
  }
  const id = header.column.id.replace(/[_.-]+/g, ' ').trim()
  return id.charAt(0).toUpperCase() + id.slice(1)
}

/**
 * Phone layout for a table with no `mobileRow`: the first data column is the
 * title, the next few become label/value fields, and the row's checkbox and
 * actions stay reachable. Built from the same cells, so it needs no per-page code.
 */
function AutoMobileCard<TData>({
  row,
  labels,
  onRowClick,
}: {
  row: Row<TData>
  labels: Map<string, string>
  onRowClick?: (row: TData) => void
}) {
  const cells = row.getVisibleCells()
  const select = cells.find((c) => c.column.id === 'select')
  const actions = cells.find((c) => c.column.id === 'actions')
  const [title, ...rest] = cells.filter((c) => !CONTROL_COLUMN_IDS.has(c.column.id))
  const fields = rest.slice(0, MOBILE_CARD_FIELDS)
  return (
    <div
      data-slot="mobile-card"
      data-state={row.getIsSelected() ? 'selected' : undefined}
      className={cn(
        'px-3 py-3 data-[state=selected]:bg-muted',
        onRowClick && 'cursor-pointer hover:bg-muted/50'
      )}
      onClick={(e) => {
        const target = e.target as HTMLElement
        if (!e.currentTarget.contains(target)) return
        if (target.closest(INTERACTIVE_SELECTOR)) return
        onRowClick?.(row.original)
      }}
    >
      {/* Header: the title keeps at least 60% of the width, so a row menu
          (the usual "...") sits beside it while wide action buttons wrap onto
          their own line instead of covering the title. */}
      <div className="flex flex-wrap items-start gap-x-3 gap-y-2">
        {select && (
          <div className="shrink-0 pt-0.5">
            {flexRender(select.column.columnDef.cell, select.getContext())}
          </div>
        )}
        {title && (
          <div className="min-w-0 flex-[1_1_60%] text-sm font-medium break-words [&_.truncate]:whitespace-normal [&_.whitespace-nowrap]:whitespace-normal">
            {flexRender(title.column.columnDef.cell, title.getContext())}
          </div>
        )}
        {actions && (
          <div className="ms-auto flex max-w-full shrink-0 flex-wrap items-center justify-end gap-2">
            {flexRender(actions.column.columnDef.cell, actions.getContext())}
          </div>
        )}
      </div>
      {fields.length > 0 && (
        // Full card width, two equal columns (minmax(0,1fr): a long value
        // cannot widen its column). break-words only splits a word that is
        // longer than the column; "High" stays whole.
        <dl
          className={cn(
            'mt-2 grid grid-cols-[repeat(2,minmax(0,1fr))] gap-x-3 gap-y-2',
            select && 'ps-7'
          )}
        >
          {fields.map((cell) => (
            <div key={cell.id} data-slot="mobile-card-field" className="min-w-0">
              <dt className="truncate text-xs text-muted-foreground">
                {labels.get(cell.column.id)}
              </dt>
              {/* Cells are written for a wide table row: whatever they keep on
                  one line (whitespace-nowrap) may wrap here, as in the title,
                  so a value never runs into the next column. A truncated cell
                  (ellipsis, one line) wraps too: the card has the room. */}
              <dd className="mt-0.5 min-w-0 text-sm break-words [&_.truncate]:whitespace-normal [&_.whitespace-nowrap]:whitespace-normal [&_[data-slot=badge]]:max-w-full [&_[data-slot=badge]]:whitespace-normal [&_[data-slot=badge]]:break-words">
                {flexRender(cell.column.columnDef.cell, cell.getContext())}
              </dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  )
}

/** Elements inside a row that act on their own instead of opening the row. */
const INTERACTIVE_SELECTOR =
  'button, a[href], input, select, textarea, label, [role="checkbox"], [role="switch"], [role="menuitem"], [data-radix-collection-item]'

const NO_ROWS: never[] = []

/**
 * A column whose definition gives no header (TanStack fills in its default,
 * which renders nothing for a column without an accessor): row actions and
 * similar. Its header cell still needs a name for screen readers.
 */
function isHeaderless<TData>(table: TanstackTable<TData>, column: Column<TData, unknown>): boolean {
  const def = column.columnDef as { header?: unknown; accessorKey?: unknown }
  if (def.accessorKey !== undefined) return false
  return def.header === undefined || def.header === table._getDefaultColumnDef().header
}

export function DataTable<TData, TValue>({
  columns,
  data,
  searchKey,
  searchPlaceholder,
  search: serverSearch,
  showColumnToggle = true,
  showPagination = true,
  showSearch = true,
  pageSize = 10,
  pageSizeOptions = [10, 20, 30, 50, 100],
  emptyMessage,
  emptyDescription,
  emptyState,
  isFiltered,
  onClearFilters,
  caption,
  staleAt,
  onRefresh,
  countUnavailable = false,
  onRetryCount,
  errorState: errorStateProp,
  error,
  onRetry,
  errorTitle,
  onRowClick,
  rowTone,
  onSelectionChange,
  manualPagination = false,
  pageCount,
  rowCount,
  rowCountCapped,
  pagination,
  onPaginationChange,
  getRowId,
  sorting: sortingProp,
  onSortingChange,
  filterToggle,
  filter,
  toolbarStart,
  toolbarEnd,
  toolbarBelow,
  stickyFirstColumn = true,
  resetSelectionKey,
  showSelectionCount = true,
  mobileRow,
  mobileCards = true,
  isLoading = false,
  isRefreshing = false,
  refreshingLabel,
  initialColumnVisibility,
  columnVisibility: columnVisibilityProp,
  onColumnVisibilityChange,
  density: densityProp,
  onDensityChange,
  rowGroups,
  paginationNoun,
  pageSizeLabel,
  defaultDensity = 'default',
  stickyHeader = false,
}: DataTableProps<TData, TValue>) {
  const { t } = useTranslation()
  const errorState =
    errorStateProp ??
    (error && data.length === 0 ? (
      <ErrorState
        title={errorTitle ?? t('common.theList', 'the list')}
        error={error}
        onRetry={onRetry}
      />
    ) : undefined)
  // Defaults are translated here, not in the signature: they depend on the locale.
  searchPlaceholder ??= t('common.table.search', 'Search…')
  emptyMessage ??= t('common.table.noResults', 'No results found')
  paginationNoun ??= t('common.table.resultsNoun', 'results')
  pageSizeLabel ??= t('common.table.rowsPerPage', 'Rows per page')
  const [storedDensity, setStoredDensity] = useTableDensity(defaultDensity)
  const density = densityProp ?? storedDensity
  const setDensity = onDensityChange ?? setStoredDensity
  const compact = density === 'compact'
  // Cards replace the table on phones. Decided in JS rather than by hiding one
  // with CSS, so only one of the two is ever rendered.
  const isPhone = useIsMobile()
  const phoneCards = isPhone && (!!mobileRow || mobileCards)
  // Which sides of the horizontally-scrolling table have content hidden under
  // the pinned columns — drives the edge shadows.
  const tableWrapRef = React.useRef<HTMLDivElement>(null)
  const [hiddenEdges, setHiddenEdges] = React.useState({ start: false, end: false })
  // Mode A (`clip`): the table fits, the page scrolls, the header sticks under
  // the app header. Mode B (`scroll`): the table is wider than its frame (the
  // viewer turned on many columns), the frame scrolls on both axes and the
  // header sticks to its top. Chosen from the measurement, never by the page.
  const [scrollMode, setScrollMode] = React.useState<'clip' | 'scroll'>('clip')
  const measureEdges = React.useCallback(() => {
    const el = tableWrapRef.current?.querySelector<HTMLElement>('[data-slot="table-container"]')
    if (!el) return
    const tableEl = el.querySelector<HTMLElement>('table')
    if (tableEl) {
      const wider = tableEl.offsetWidth > el.clientWidth + 1
      setScrollMode((prev) => (wider ? 'scroll' : prev === 'scroll' ? 'clip' : prev))
    }
    // Group headers span the visible frame, not the scrolling table, so their
    // name and actions stay in view while the rows scroll sideways.
    tableWrapRef.current?.style.setProperty('--dt-frame', `${el.clientWidth}px`)
    const x = Math.abs(el.scrollLeft)
    const next = { start: x > 0, end: el.scrollWidth - el.clientWidth - x > 1 }
    setHiddenEdges((prev) => (prev.start === next.start && prev.end === next.end ? prev : next))
  }, [])
  const [internalSorting, setInternalSorting] = React.useState<SortingState>([])
  const serverSorting = manualPagination && !!onSortingChange
  const sorting = serverSorting ? (sortingProp ?? []) : internalSorting
  const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>([])
  const [ownVisibility, setOwnVisibility] = React.useState<VisibilityState>(
    () => initialColumnVisibility ?? {}
  )
  const columnVisibility = columnVisibilityProp ?? ownVisibility
  // Column priority: a column whose `meta.hideBelow` is wider than the
  // table's frame is hidden, so a narrow screen drops the least important
  // columns instead of scrolling the table sideways. A column the viewer
  // turned on or off under Columns keeps that choice (the state has its key);
  // the menu shows an auto-hidden column as off, so turning it on is one click.
  const [frameWidth, setFrameWidth] = React.useState(0)
  React.useEffect(() => {
    const el = tableWrapRef.current
    if (!el || typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(() => setFrameWidth(el.clientWidth))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  const effectiveVisibility = React.useMemo(() => {
    if (frameWidth === 0) return columnVisibility
    const auto: VisibilityState = {}
    for (const c of columns) {
      const hideBelow = (c.meta as { hideBelow?: number } | undefined)?.hideBelow
      if (c.id && hideBelow && frameWidth < hideBelow) auto[c.id] = false
    }
    return { ...auto, ...columnVisibility }
  }, [columns, columnVisibility, frameWidth])
  const columnVisibilityRef = React.useRef(columnVisibility)
  columnVisibilityRef.current = columnVisibility
  const setColumnVisibility = React.useCallback(
    (updater: VisibilityState | ((old: VisibilityState) => VisibilityState)) => {
      const next = typeof updater === 'function' ? updater(columnVisibilityRef.current) : updater
      if (columnVisibilityProp !== undefined || onColumnVisibilityChange) {
        onColumnVisibilityChange?.(next)
      } else {
        setOwnVisibility(next)
      }
    },
    [columnVisibilityProp, onColumnVisibilityChange]
  )
  const [rowSelection, setRowSelection] = React.useState({})
  // Named by the page title when no caption is given (found after mount: the
  // PageHeader is a sibling of the table, not an ancestor).
  const [labelledBy, setLabelledBy] = React.useState<string | undefined>(undefined)
  React.useEffect(() => {
    if (caption) return
    setLabelledBy(document.getElementById(PAGE_TITLE_ID) ? PAGE_TITLE_ID : undefined)
  }, [caption])
  const [globalFilter, setGlobalFilter] = React.useState('')
  // "Try adjusting your search" only makes sense while one is applied: an
  // empty list with no search or filter says just what is empty.
  const filterActive =
    isFiltered ??
    (Boolean(globalFilter) || Boolean(serverSearch?.value) || columnFilters.length > 0)
  const emptyHint =
    emptyDescription ??
    (filterActive
      ? t('common.table.adjustSearch', 'Try adjusting your search or filters')
      : undefined)
  const rowGroupsRef = React.useRef(rowGroups)
  rowGroupsRef.current = rowGroups
  const [sortedRowModel] = React.useState(() =>
    groupSortedRowModel<TData>(getSortedRowModel(), () => rowGroupsRef.current)
  )
  const groupExpansion = useGroupExpansion(rowGroups)

  const table = useReactTable({
    // A failed read shows its error instead of rows left over from an earlier one.
    data: errorState ? (NO_ROWS as TData[]) : data,
    columns,
    ...(getRowId ? { getRowId } : {}),
    onSortingChange: serverSorting
      ? (updater) => onSortingChange(typeof updater === 'function' ? updater(sorting) : updater)
      : setInternalSorting,
    // An empty list has nothing to order: its headers are plain labels.
    enableSorting: (!manualPagination || serverSorting) && data.length > 0,
    enableMultiSort: false,
    onColumnFiltersChange: setColumnFilters,
    getCoreRowModel: getCoreRowModel(),
    // In manual (server) pagination the parent already fetched exactly one page,
    // so the table must NOT slice the rows again — omit getPaginationRowModel.
    // Under manual (server) pagination the parent fetched exactly one page, so
    // the table must not slice, sort OR filter the rows again. It previously
    // still did the latter two, which looked global but only ever touched the
    // rows on screen — a sort that silently reorders 20 of 6000 findings is
    // worse than no sort at all. Tell tanstack the server owns all three.
    ...(manualPagination
      ? { manualSorting: true, manualFiltering: true }
      : {
          getPaginationRowModel: getPaginationRowModel(),
          getSortedRowModel: sortedRowModel,
          getFilteredRowModel: getFilteredRowModel(),
        }),
    onColumnVisibilityChange: setColumnVisibility,
    onRowSelectionChange: setRowSelection,
    onGlobalFilterChange: setGlobalFilter,
    globalFilterFn: 'includesString',
    manualPagination,
    // Prefer rowCount (tanstack derives pageCount); fall back to explicit pageCount.
    ...(manualPagination
      ? rowCount != null && !countUnavailable
        ? { rowCount }
        : { pageCount: countUnavailable ? -1 : (pageCount ?? -1) }
      : {}),
    // Only under manual pagination. Passing `onPaginationChange: undefined`
    // otherwise overrides tanstack's own state updater (options are spread over
    // its defaults), which left every client-paginated table stuck on page 1:
    // Next, Last and the page-size select did nothing.
    ...(manualPagination
      ? {
          onPaginationChange: (
            updater:
              | { pageIndex: number; pageSize: number }
              | ((old: { pageIndex: number; pageSize: number }) => {
                  pageIndex: number
                  pageSize: number
                })
          ) => {
            const current = pagination ?? { pageIndex: 0, pageSize }
            const next = typeof updater === 'function' ? updater(current) : updater
            onPaginationChange?.(next)
          },
        }
      : {}),
    state: {
      sorting,
      columnFilters,
      columnVisibility: effectiveVisibility,
      rowSelection,
      globalFilter,
      ...(manualPagination && pagination ? { pagination } : {}),
    },
    initialState: {
      pagination: {
        pageSize,
      },
    },
  })

  // Field labels for the automatic phone cards.
  const mobileLabels = new Map<string, string>()
  if (phoneCards && !mobileRow) {
    for (const header of table.getFlatHeaders()) {
      mobileLabels.set(header.column.id, columnLabel(header as Header<TData, unknown>))
    }
  }

  // Pinned columns: the selection checkbox (if first) + the first data column.
  const visibleColumns = table.getVisibleLeafColumns()
  const selectColumn = visibleColumns[0]?.id === 'select' ? visibleColumns[0] : undefined
  const firstDataColumn = visibleColumns.find((c) => c.id !== 'select' && c.id !== 'actions')
  const pinned = new Map<string, { start: number; last: boolean }>()
  const actionsPinned =
    stickyFirstColumn && visibleColumns[visibleColumns.length - 1]?.id === 'actions'
  if (stickyFirstColumn && firstDataColumn) {
    if (selectColumn) pinned.set(selectColumn.id, { start: 0, last: false })
    pinned.set(firstDataColumn.id, { start: selectColumn ? SELECT_COL_WIDTH : 0, last: true })
  }
  const pinnedPropsBase = (columnId: string) => {
    const isSelect = columnId === 'select'
    const width = isSelect
      ? { width: SELECT_COL_WIDTH, minWidth: SELECT_COL_WIDTH, maxWidth: SELECT_COL_WIDTH }
      : {}
    if (columnId === 'actions' && actionsPinned) {
      return {
        className: cn(PINNED_CELL_CLASS, PINNED_END_EDGE_CLASS),
        style: { insetInlineEnd: 0 },
      }
    }
    const pin = pinned.get(columnId)
    if (!pin) return { className: undefined, style: isSelect ? width : undefined }
    return {
      className: cn(
        PINNED_CELL_CLASS,
        pin.last && PINNED_START_EDGE_CLASS,
        // The pinned name column must leave room for the columns that scroll:
        // cap it and let long names wrap instead of widening the pin. It also
        // keeps a floor: in an automatic table layout a truncating name has no
        // minimum width, so ten other columns squeezed it to a few letters
        // ("e2..."); with the floor the other columns scroll instead.
        pin.last && cn(NAME_COLUMN_FLOOR, 'max-w-[min(26rem,38vw)] whitespace-normal')
      ),
      style: { ...width, insetInlineStart: pin.start },
    }
  }

  // A column marked `meta: { primary: true }` (the row's name when it is not
  // the first column, e.g. a finding title after its priority) gets the same
  // floor as the pinned name column, so other columns cannot squeeze it.
  const pinnedProps = (columnId: string) => {
    const props = pinnedPropsBase(columnId)
    const primary = (table.getColumn(columnId)?.columnDef.meta as { primary?: boolean } | undefined)
      ?.primary
    return primary ? { ...props, className: cn(props.className, NAME_COLUMN_FLOOR) } : props
  }

  // Re-measure when the rows, visible columns or container size change.
  React.useEffect(() => {
    measureEdges()
    const el = tableWrapRef.current?.querySelector<HTMLElement>('[data-slot="table-container"]')
    if (!el || typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(measureEdges)
    ro.observe(el)
    return () => ro.disconnect()
  }, [measureEdges, data, effectiveVisibility])

  // Clear the selection whenever the parent bumps resetSelectionKey, and
  // whenever a server-paged table changes page, page size or sort: the rows
  // the selection was made on are no longer the rows on screen, and a bulk
  // action must never reach rows the user cannot see.
  const pageScope = manualPagination
    ? `${pagination?.pageIndex ?? 0}|${pagination?.pageSize ?? pageSize}|${JSON.stringify(sorting)}`
    : ''
  const lastResetKey = React.useRef(`${resetSelectionKey}|${pageScope}`)
  React.useEffect(() => {
    const next = `${resetSelectionKey}|${pageScope}`
    if (lastResetKey.current === next) return
    lastResetKey.current = next
    setRowSelection({})
  }, [resetSelectionKey, pageScope])

  // Rows of this page in display order: one pseudo-group without rowGroups.
  const pageRows = table.getRowModel().rows
  const displayGroups = !rowGroups
    ? [{ key: 'all', rows: pageRows }]
    : rowGroups.groups
      ? rowsForServerGroups(pageRows, (r) => rowGroups.getKey(r.original), rowGroups.groups)
      : groupRowsForDisplay(pageRows, (r) => rowGroups.getKey(r.original), rowGroups.order)
  // Client groups: every row of each group across pages, for the header's counts.
  const wholeGroups = new Map<string, TData[]>()
  if (rowGroups && !rowGroups.groups && !manualPagination) {
    for (const r of table.getPrePaginationRowModel().rows) {
      const k = rowGroups.getKey(r.original)
      const list = wholeGroups.get(k)
      if (list) list.push(r.original)
      else wholeGroups.set(k, [r.original])
    }
  }
  // Server groups render their headers before any of their rows are loaded.
  const hasBody = pageRows.length > 0 || (rowGroups?.groups?.length ?? 0) > 0
  const canSelectGroups = table.getAllLeafColumns().some((c) => c.id === 'select')
  const groupDomId = React.useId()
  const groupIds = (key: string) => {
    const safe = `${groupDomId}-${encodeURIComponent(key).replace(/%/g, '_')}`
    return { header: `${safe}-h`, rows: `${safe}-r` }
  }

  const selectedCount = table.getFilteredSelectedRowModel().rows.length
  const totalCount = table.getFilteredRowModel().rows.length

  // Lift the internally-owned selection up to an optional parent callback so a
  // bulk-action bar can react. Ref keeps the effect from depending on an inline
  // callback identity (which would refire every render).
  const onSelectionChangeRef = React.useRef(onSelectionChange)
  onSelectionChangeRef.current = onSelectionChange
  React.useEffect(() => {
    onSelectionChangeRef.current?.(table.getFilteredSelectedRowModel().rows.map((r) => r.original))
    // `table` is the same instance for the component's lifetime (useReactTable
    // keeps it in state), so only a selection change re-runs this.
  }, [rowSelection, table])

  // Rows the footer pages through: the server's count under manual pagination,
  // else the rows left after client-side filtering.
  const paginationTotal = manualPagination
    ? (rowCount ?? data.length)
    : table.getFilteredRowModel().rows.length

  // Column kinds: alignment and widths of a column's header and cells.
  const layoutOf = (columnId: string) =>
    columnLayout(columnId, table.getColumn(columnId)?.columnDef.meta)
  const cellProps = (columnId: string, head: boolean) => {
    const pin = pinnedProps(columnId)
    const layout = layoutOf(columnId)
    return {
      className: cn(
        pin.className,
        ALIGN_CLASS[layout.align],
        head && stickyHeader && STICKY_HEAD_CLASS,
        head &&
          stickyHeader &&
          (pin.className || columnId === 'actions') &&
          STICKY_HEAD_PINNED_CLASS,
        // The page's scroller is <main>, under the app header: top 0 sticks the
        // header there (Mode A) or at the frame's top (Mode B, the frame scrolls).
        head && stickyHeader && 'top-0',
        !head && compact && COMPACT_CELL_CLASS
      ),
      style: layout.style || pin.style ? { ...layout.style, ...pin.style } : undefined,
    }
  }

  // One polite live region per table: sort, page and refresh results.
  const sortKey = sorting.map((s) => `${s.id}:${s.desc ? 'd' : 'a'}`).join(',')
  const pageIndex = table.getState().pagination.pageIndex
  const announce = useTableAnnouncements({
    sortKey,
    sortMessage: () => {
      const s = sorting[0]
      if (!s) return ''
      const header = table.getFlatHeaders().find((h) => h.column.id === s.id)
      const label = header ? columnLabel(header as Header<TData, unknown>) : s.id
      return t('common.table.sortedBy', 'Sorted by {column}, {direction}', {
        column: label,
        direction: s.desc
          ? t('common.table.descending', 'descending')
          : t('common.table.ascending', 'ascending'),
      })
    },
    pageIndex,
    pageMessage: () =>
      countUnavailable
        ? t('common.table.pageOnly', 'Page {page}', { page: pageIndex + 1 })
        : t('common.table.pageOf', 'Page {page} of {pages}', {
            page: pageIndex + 1,
            pages: Math.max(1, table.getPageCount()),
          }),
    refreshing: isRefreshing,
    refreshedMessage: () =>
      t('common.table.resultsCount', '{count} {noun}', {
        count: paginationTotal.toLocaleString(),
        noun: paginationNoun,
      }),
  })

  // The empty body: one block, or the two kinds of empty list.
  const emptyBody = isEmptyStates(emptyState)
    ? filterActive
      ? (emptyState.noMatch ?? (
          <DefaultEmpty
            message={t('common.table.noResults', 'No results found')}
            hint={t('common.table.adjustSearch', 'Try adjusting your search or filters')}
            action={
              onClearFilters ? (
                <Button variant="outline" size="sm" onClick={onClearFilters}>
                  {t('common.table.clearFilters', 'Clear filters')}
                </Button>
              ) : undefined
            }
          />
        ))
      : emptyState.nothingYet
    : (emptyState ?? <DefaultEmpty message={emptyMessage} hint={emptyHint} />)

  // A stale read says so in the footer, with a refresh.
  const staleNote = staleAt ? (
    <span data-slot="table-stale" className="inline-flex items-center gap-1">
      {t('common.table.updated', 'Updated')} <RelativeTime date={staleAt} />
      {onRefresh && (
        <Button
          variant="ghost"
          size="icon"
          aria-label={t('common.table.refreshNow', 'Refresh now')}
          onClick={onRefresh}
        >
          <RefreshCw className="size-4" />
        </Button>
      )}
    </span>
  ) : null

  return (
    <div className="space-y-4">
      {/* Toolbar: the shared ListToolbar row (order and wrapping rules live
          there). */}
      <ListToolbar
        filterToggle={filterToggle}
        filter={filter}
        search={
          serverSearch ??
          (showSearch
            ? {
                value: searchKey
                  ? ((table.getColumn(searchKey)?.getFilterValue() as string) ?? '')
                  : globalFilter,
                onChange: (value: string) => {
                  if (searchKey) table.getColumn(searchKey)?.setFilterValue(value)
                  else setGlobalFilter(value)
                },
                placeholder: searchPlaceholder,
              }
            : undefined)
        }
        start={toolbarStart}
        below={toolbarBelow}
        end={
          <>
            {toolbarEnd}
            {/* Selection info - hidden on mobile when no selection */}
            {showSelectionCount && selectedCount > 0 && (
              <span className="text-sm text-muted-foreground hidden sm:inline">
                {t('common.table.selectedOf', '{selected} of {total} selected', {
                  selected: selectedCount,
                  total: totalCount,
                })}
              </span>
            )}

            {/* Display menu: row density (every table, D14) and, when the
              table allows it, which columns show. Named "Display" so it is
              never confused with saved "Views". */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  className={cn('h-9', phoneCards && 'hidden')}
                  aria-label={t('common.table.displayMenu', 'Display: density and columns')}
                >
                  <SlidersHorizontal className="h-4 w-4 @xl/toolbar:me-2" />
                  <span className="sr-only @xl/toolbar:not-sr-only">
                    {t('common.table.display', 'Display')}
                  </span>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-[200px]">
                <DropdownMenuLabel className="text-xs text-muted-foreground">
                  {t('common.table.density', 'Density')}
                </DropdownMenuLabel>
                <DropdownMenuRadioGroup
                  value={density}
                  onValueChange={(v) => setDensity(v as TableDensity)}
                >
                  {TABLE_DENSITIES.map((d) => (
                    <DropdownMenuRadioItem key={d} value={d}>
                      {t(DENSITY_LABEL_KEYS[d][0], DENSITY_LABEL_KEYS[d][1])}
                    </DropdownMenuRadioItem>
                  ))}
                </DropdownMenuRadioGroup>
                {showColumnToggle && (
                  <>
                    <DropdownMenuSeparator />
                    <DropdownMenuLabel className="text-xs text-muted-foreground">
                      {t('common.table.columns', 'Columns')}
                    </DropdownMenuLabel>
                  </>
                )}
                {showColumnToggle &&
                  table
                    .getAllColumns()
                    .filter((column) => column.getCanHide())
                    .map((column) => {
                      return (
                        <DropdownMenuCheckboxItem
                          key={column.id}
                          className="capitalize"
                          checked={column.getIsVisible()}
                          onCheckedChange={(value) => column.toggleVisibility(!!value)}
                        >
                          {(column.columnDef.meta as { label?: string } | undefined)?.label ??
                            column.id.replace(/_/g, ' ')}
                        </DropdownMenuCheckboxItem>
                      )
                    })}
              </DropdownMenuContent>
            </DropdownMenu>
          </>
        }
      />

      {phoneCards && (
        <div className="relative divide-y overflow-hidden rounded-md border">
          <TableRefreshBar active={isRefreshing} label={refreshingLabel} />
          {hasBody ? (
            displayGroups.map((group) => {
              const expanded = groupExpansion.isExpanded(group.key)
              const ids = groupIds(group.key)
              const footer =
                rowGroups && expanded
                  ? rowGroups.renderFooter?.(
                      group.key,
                      group.rows.map((r) => r.original)
                    )
                  : null
              const loading =
                rowGroups && expanded && group.rows.length === 0 && rowGroups.isGroupLoading
                  ? rowGroups.isGroupLoading(group.key)
                  : false
              return (
                <div
                  key={`group-${group.key}`}
                  role={rowGroups ? 'group' : undefined}
                  aria-labelledby={rowGroups ? ids.header : undefined}
                  className="divide-y"
                >
                  {rowGroups && (
                    <div
                      data-slot="row-group-header"
                      className="bg-muted/50 px-3 py-2 text-xs text-muted-foreground"
                    >
                      <GroupHeaderContent
                        rowGroups={rowGroups}
                        groupKey={group.key}
                        rows={group.rows}
                        groupRows={wholeGroups.get(group.key)}
                        expanded={expanded}
                        onToggle={() => groupExpansion.toggle(group.key)}
                        canSelect={canSelectGroups && !mobileRow}
                        controlsId={ids.rows}
                        headerId={ids.header}
                      />
                    </div>
                  )}
                  {expanded && (
                    <div id={ids.rows} className="divide-y">
                      {group.rows.map((row) =>
                        mobileRow ? (
                          <div key={row.id}>
                            {mobileRow(row.original, {
                              selectable: canSelectGroups,
                              selected: row.getIsSelected(),
                              onSelectedChange: (v) => row.toggleSelected(v),
                            })}
                          </div>
                        ) : (
                          <AutoMobileCard
                            key={row.id}
                            row={row}
                            labels={mobileLabels}
                            onRowClick={onRowClick}
                          />
                        )
                      )}
                      {loading && (
                        <div
                          aria-busy="true"
                          aria-label={t('common.table.loading', 'Loading')}
                          className="space-y-2 px-3 py-3"
                        >
                          <Skeleton className="h-4 w-2/3" />
                          <Skeleton className="h-3 w-1/3" />
                        </div>
                      )}
                      {footer && <div className="px-3 py-2 text-xs">{footer}</div>}
                    </div>
                  )}
                </div>
              )
            })
          ) : isLoading ? (
            <div aria-busy="true" aria-label={t('common.table.loading', 'Loading')}>
              {Array.from({ length: LOADING_ROWS }).map((_, i) => (
                <div key={i} className="space-y-2 px-3 py-3">
                  <Skeleton className="h-4 w-2/3" />
                  <Skeleton className="h-3 w-1/3" />
                </div>
              ))}
            </div>
          ) : (
            (errorState ??
            (emptyState === undefined || isEmptyStates(emptyState) ? (
              <div className="py-12">{emptyBody}</div>
            ) : (
              emptyBody
            )))
          )}
        </div>
      )}

      {/* Table */}
      <div
        ref={tableWrapRef}
        className={cn(
          'group/table relative overflow-clip rounded-md border',
          phoneCards && 'hidden'
        )}
        data-density={density}
        data-scroll-mode={scrollMode}
        data-hidden-start={hiddenEdges.start}
        data-hidden-end={hiddenEdges.end}
        // scroll does not bubble, but a capture listener on an ancestor sees the
        // inner table container's scroll.
        onScrollCapture={(e) => {
          if ((e.target as HTMLElement).dataset.slot === 'table-container') measureEdges()
        }}
      >
        <TableRefreshBar active={isRefreshing} label={refreshingLabel} />
        <Table
          {...DENSE_ATTRS}
          scroll={stickyHeader ? scrollMode : 'scroll'}
          containerStyle={stickyHeader && scrollMode === 'scroll' ? SCROLL_FRAME_STYLE : undefined}
          aria-labelledby={caption ? undefined : labelledBy}
          aria-busy={isLoading && !hasBody ? true : undefined}
        >
          {caption && <caption className="sr-only">{caption}</caption>}
          <TableHeader>
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id}>
                {headerGroup.headers.map((header) => {
                  return (
                    <TableHead
                      key={header.id}
                      {...cellProps(header.column.id, true)}
                      aria-sort={
                        header.column.getCanSort()
                          ? ariaSort(header.column.getIsSorted())
                          : undefined
                      }
                    >
                      {header.isPlaceholder ? null : !isHeaderless(table, header.column) ? (
                        flexRender(header.column.columnDef.header, header.getContext())
                      ) : (
                        // A column with no visible header (row actions, the
                        // selection box) still names itself to screen readers.
                        <span className="sr-only">
                          {header.column.id === 'select'
                            ? t('common.table.selectColumn', 'Select')
                            : t('common.table.actionsColumn', 'Actions')}
                        </span>
                      )}
                    </TableHead>
                  )
                })}
              </TableRow>
            ))}
          </TableHeader>
          {hasBody ? (
            displayGroups.map((group, gi) => {
              const expanded = groupExpansion.isExpanded(group.key)
              const ids = groupIds(group.key)
              const loading =
                rowGroups && expanded && group.rows.length === 0 && rowGroups.isGroupLoading
                  ? rowGroups.isGroupLoading(group.key)
                  : false
              const footer =
                rowGroups && expanded
                  ? rowGroups.renderFooter?.(
                      group.key,
                      group.rows.map((r) => r.original)
                    )
                  : null
              return (
                // One tbody per group: a native row group, named by its header.
                <TableBody
                  key={`group-${group.key}`}
                  id={rowGroups ? ids.rows : undefined}
                  aria-labelledby={rowGroups ? ids.header : undefined}
                  className={cn(gi < displayGroups.length - 1 && '[&_tr:last-child]:border-b')}
                >
                  {rowGroups && (
                    <TableRow data-slot="row-group-header" className="hover:bg-transparent">
                      <TableCell
                        colSpan={table.getVisibleLeafColumns().length}
                        className="bg-muted/50 py-2 text-xs text-muted-foreground"
                      >
                        <div className="sticky start-2 w-[calc(var(--dt-frame,100%)-1rem)] max-w-full">
                          <GroupHeaderContent
                            rowGroups={rowGroups}
                            groupKey={group.key}
                            rows={group.rows}
                            groupRows={wholeGroups.get(group.key)}
                            expanded={expanded}
                            onToggle={() => groupExpansion.toggle(group.key)}
                            canSelect={canSelectGroups}
                            controlsId={ids.rows}
                            headerId={ids.header}
                          />
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                  {expanded &&
                    group.rows.map((row) => (
                      <TableRow
                        key={row.id}
                        data-state={row.getIsSelected() && 'selected'}
                        data-tone={rowTone?.(row.original)}
                        className={cn(
                          'group/row',
                          onRowClick && 'cursor-pointer hover:bg-muted/50'
                        )}
                        onClick={(e) => {
                          const target = e.target as HTMLElement
                          // React bubbles events out of portals: a click inside a row's
                          // open menu, or a dialog opened from it, reaches this handler
                          // although it is not in the row's DOM. Only real row clicks count.
                          if (!e.currentTarget.contains(target)) return
                          // Nor clicks on the row's own controls.
                          const isInteractiveElement = target.closest(INTERACTIVE_SELECTOR)

                          if (!isInteractiveElement && onRowClick) {
                            onRowClick(row.original)
                          }
                        }}
                      >
                        {row.getVisibleCells().map((cell) => (
                          <TableCell key={cell.id} {...cellProps(cell.column.id, false)}>
                            {flexRender(cell.column.columnDef.cell, cell.getContext())}
                          </TableCell>
                        ))}
                      </TableRow>
                    ))}
                  {loading &&
                    Array.from({ length: 2 }).map((_, i) => (
                      <TableRow
                        key={`group-loading-${i}`}
                        aria-busy="true"
                        data-loading-row=""
                        className="hover:bg-transparent"
                      >
                        {table.getVisibleLeafColumns().map((column) => (
                          <TableCell key={column.id}>
                            <Skeleton
                              className={cn(
                                'h-4',
                                column.id === 'select' ? 'w-4' : 'w-full max-w-40'
                              )}
                            />
                          </TableCell>
                        ))}
                      </TableRow>
                    ))}
                  {footer && (
                    <TableRow data-slot="row-group-footer" className="hover:bg-transparent">
                      <TableCell
                        colSpan={table.getVisibleLeafColumns().length}
                        className="py-1.5 text-xs text-muted-foreground"
                      >
                        <div className="sticky start-2 w-[calc(var(--dt-frame,100%)-1rem)] max-w-full">
                          {footer}
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              )
            })
          ) : (
            <TableBody>
              {isLoading ? (
                Array.from({ length: LOADING_ROWS }).map((_, i) => (
                  <TableRow key={`loading-${i}`} aria-busy="true" data-loading-row="">
                    {table.getVisibleLeafColumns().map((column) => (
                      <TableCell key={column.id}>
                        <Skeleton
                          className={cn('h-4', column.id === 'select' ? 'w-4' : 'w-full max-w-40')}
                        />
                      </TableCell>
                    ))}
                  </TableRow>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={columns.length} className="h-48 text-center">
                    {errorState ?? emptyBody}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          )}
        </Table>
      </div>

      {/* The table's polite live region: sort, page and refresh results. */}
      <div role="status" aria-live="polite" className="sr-only" data-slot="table-announcer">
        {announce}
      </div>

      {/* A stale read with no pager (an empty list) still says how old it is. */}
      {staleNote && !(showPagination && !errorState && paginationTotal > 0) && (
        <div className="text-cap text-muted-foreground">{staleNote}</div>
      )}

      {/* Pagination. Hidden while there is no row to page through (an empty
          list, or the first load): never "Showing 0 - 0 of 0" or
          "Page 1 of 0". */}
      {showPagination && !errorState && paginationTotal > 0 && (
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          {/* Row count info - centered on mobile. Under manual pagination the
              total is the server row count, not the current page's length. */}
          {(() => {
            const { pageIndex, pageSize: ps } = table.getState().pagination
            const total = manualPagination
              ? (rowCount ?? data.length)
              : table.getFilteredRowModel().rows.length
            const start = total === 0 ? 0 : pageIndex * ps + 1
            const end = countUnavailable
              ? pageIndex * ps + data.length
              : Math.min((pageIndex + 1) * ps, total)
            return (
              <div className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1 text-sm text-muted-foreground sm:justify-start">
                {staleNote}
                {countUnavailable ? (
                  <>
                    <span>
                      {t('common.table.showingNoTotal', 'Showing {start} - {end}', {
                        start,
                        end,
                      })}
                    </span>
                    <span
                      data-slot="table-count-unavailable"
                      className="inline-flex items-center gap-1"
                    >
                      {t('common.table.countUnavailable', 'Could not count')}
                      {onRetryCount && (
                        <Button variant="ghost" size="sm" onClick={onRetryCount}>
                          {t('common.retry', 'Retry')}
                        </Button>
                      )}
                    </span>
                  </>
                ) : (
                  <span>
                    {t('common.table.showing', 'Showing {start} - {end} of {total} {noun}', {
                      start,
                      end,
                      total: rowCountCapped
                        ? t('common.table.cappedCount', '{count}+', {
                            count: total.toLocaleString(),
                          })
                        : total,
                      noun: paginationNoun,
                    })}
                  </span>
                )}
              </div>
            )
          })()}

          {/* Pagination controls - centered on mobile */}
          <div className="flex flex-wrap items-center justify-center sm:justify-end gap-2 sm:gap-4">
            {/* Page size selector */}
            <div className="hidden sm:flex items-center gap-2">
              <span className="text-sm text-muted-foreground">{pageSizeLabel}</span>
              <Select
                value={`${table.getState().pagination.pageSize}`}
                onValueChange={(value) => {
                  table.setPageSize(Number(value))
                }}
              >
                <SelectTrigger
                  className="h-8 w-[70px]"
                  aria-label={`${pageSizeLabel}: ${table.getState().pagination.pageSize}`}
                >
                  <SelectValue placeholder={table.getState().pagination.pageSize} />
                </SelectTrigger>
                <SelectContent side="top">
                  {pageSizeChoices(pageSizeOptions, table.getState().pagination.pageSize).map(
                    (size) => (
                      <SelectItem key={size} value={`${size}`}>
                        {size}
                      </SelectItem>
                    )
                  )}
                </SelectContent>
              </Select>
            </div>

            {/* Page navigation */}
            <div className="flex items-center gap-1">
              <Button
                variant="outline"
                size="icon"

                aria-label={t('common.table.firstPage', 'First page')}
                onClick={() => table.setPageIndex(0)}
                disabled={!table.getCanPreviousPage()}
              >
                <ChevronsLeft className="h-4 w-4" />
              </Button>
              <Button
                variant="outline"
                size="icon"

                aria-label={t('common.table.previousPage', 'Previous page')}
                onClick={() => table.previousPage()}
                disabled={!table.getCanPreviousPage()}
              >
                <ChevronLeft className="h-4 w-4" />
              </Button>

              {/* Page indicator */}
              <span className="text-sm text-muted-foreground">
                {countUnavailable
                  ? t('common.table.pageOnly', 'Page {page}', {
                      page: table.getState().pagination.pageIndex + 1,
                    })
                  : t('common.table.pageOf', 'Page {page} of {pages}', {
                      page: table.getState().pagination.pageIndex + 1,
                      pages: Math.max(1, table.getPageCount()),
                    })}
              </span>

              <Button
                variant="outline"
                size="icon"

                aria-label={t('common.table.nextPage', 'Next page')}
                onClick={() => table.nextPage()}
                disabled={!table.getCanNextPage()}
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
              <Button
                variant="outline"
                size="icon"

                aria-label={t('common.table.lastPage', 'Last page')}
                onClick={() => table.setPageIndex(table.getPageCount() - 1)}
                // Without a known total there is no last page to go to.
                disabled={countUnavailable || !table.getCanNextPage()}
              >
                <ChevronsRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

/** The default empty block: icon, one line, an optional hint and action. */
function DefaultEmpty({
  message,
  hint,
  action,
}: {
  message: React.ReactNode
  hint?: React.ReactNode
  action?: React.ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 text-center">
      <Inbox className="size-10 text-muted-foreground/50" />
      <p className="text-body font-medium">{message}</p>
      {hint && <p className="text-cap text-muted-foreground">{hint}</p>}
      {action}
    </div>
  )
}

/**
 * What the table's live region says: the new sort, the new page, and the
 * result count when a refresh ends. Nothing on the first render (the page
 * title and the table already say what is on screen).
 */
function useTableAnnouncements({
  sortKey,
  sortMessage,
  pageIndex,
  pageMessage,
  refreshing,
  refreshedMessage,
}: {
  sortKey: string
  sortMessage: () => string
  pageIndex: number
  pageMessage: () => string
  refreshing: boolean
  refreshedMessage: () => string
}): string {
  const [message, setMessage] = React.useState('')
  const messages = React.useRef({ sortMessage, pageMessage, refreshedMessage })
  React.useLayoutEffect(() => {
    messages.current = { sortMessage, pageMessage, refreshedMessage }
  })
  const last = React.useRef({ sortKey, pageIndex, refreshing })
  React.useEffect(() => {
    const prev = last.current
    last.current = { sortKey, pageIndex, refreshing }
    if (prev.sortKey !== sortKey) setMessage(messages.current.sortMessage())
    else if (prev.pageIndex !== pageIndex) setMessage(messages.current.pageMessage())
    else if (prev.refreshing && !refreshing) setMessage(messages.current.refreshedMessage())
  }, [sortKey, pageIndex, refreshing])
  return message
}
