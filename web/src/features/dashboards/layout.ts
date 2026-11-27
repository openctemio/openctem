/**
 * Shared layout constants for customizable dashboards (RFC-021).
 *
 * A dashboard renders as `columns` equal columns (1..4). Each widget stores its
 * width `w` on a 12-unit grid (so templates and older layouts keep working); at
 * render time that width is mapped to a column span of 1..columns. Rows are as
 * tall as their content; a widget's stored height `h` is the number of rows it
 * spans beside its neighbours, never a floor.
 */

/** Underlying grid the stored `w` is expressed in. */
export const BASE_GRID = 12

/** Default number of columns a dashboard is arranged in. */
export const DEFAULT_COLUMNS = 2

/** Clamp a raw columns value to the supported 1..4 range (default 2). */
export function normalizeColumns(columns: number | undefined): number {
  const c = Math.round(columns ?? DEFAULT_COLUMNS)
  return Math.max(1, Math.min(4, c || DEFAULT_COLUMNS))
}

/** Tailwind classes giving an N-column grid (stacked on mobile). */
export function columnsClass(columns: number | undefined): string {
  switch (normalizeColumns(columns)) {
    case 1:
      return 'grid-cols-1'
    case 3:
      return 'grid-cols-1 md:grid-cols-3'
    case 4:
      // Two columns from the smallest phone: single-figure tiles sit two
      // abreast (`--span-xs` 1), everything else takes the full row.
      return 'grid-cols-2 xl:grid-cols-4'
    default:
      return 'grid-cols-1 md:grid-cols-2'
  }
}

/** Column span (1..columns) for a widget of stored width `w`. */
export function colSpanFor(w: number, columns: number | undefined): number {
  const cols = normalizeColumns(columns)
  const unit = BASE_GRID / cols
  return Math.max(1, Math.min(cols, Math.round((w || unit) / unit)))
}

/** Stored width (12-grid units) for a widget spanning `span` of `columns`. */
export function widthFromSpan(span: number, columns: number | undefined): number {
  const cols = normalizeColumns(columns)
  const s = Math.max(1, Math.min(cols, Math.round(span)))
  return Math.min(BASE_GRID, s * (BASE_GRID / cols))
}

/** CSS `grid-column` value for a widget of span `span`. */
export function gridColumnSpan(span: number): string {
  const s = Math.max(1, Math.min(4, span))
  return `span ${s} / span ${s}`
}

/**
 * A compact widget (one column wide and one row tall in a four-column
 * dashboard: a single figure) shares a phone row with its neighbour; any
 * other widget spans the phone's two columns.
 */
export function phoneSpan(w: number, h: number, columns: number | undefined): string {
  return colSpanFor(w, columns) === 1 && (h || 1) === 1 ? gridColumnSpan(1) : gridColumnSpan(2)
}

/** CSS `grid-row` value for a widget of height `h` (in row units). */
export function widgetRowSpan(h: number): string {
  const span = Math.max(1, Math.min(8, h || 1))
  return `span ${span} / span ${span}`
}

/**
 * Classes that apply a widget's column span only once the grid has that many
 * columns (see `columnsClass`). The span arrives in `--span` (and, for four
 * columns, the two-column span in `--span-sm`). A span applied on a one-column
 * phone grid would create zero-width implicit columns and hide the widget.
 */
export function widgetSpanClass(columns: number | undefined): string {
  switch (normalizeColumns(columns)) {
    case 1:
      return ''
    case 4:
      return '[grid-column:var(--span-xs)] sm:[grid-column:var(--span-sm)] xl:[grid-column:var(--span)]'
    default:
      return 'md:[grid-column:var(--span)]'
  }
}

/**
 * The editor's grid: one column on a phone (a list of widgets with their
 * handles and menus), the dashboard's columns from the same breakpoints as
 * the view above that. Spans arrive in `--span` / `--span-sm` and apply only
 * once the grid has the columns (see `widgetSpanClass`).
 */
export function editorColumnsClass(columns: number | undefined): string {
  switch (normalizeColumns(columns)) {
    case 1:
      return 'grid-cols-1'
    case 3:
      return 'grid-cols-1 md:grid-cols-3'
    case 4:
      return 'grid-cols-1 sm:grid-cols-2 xl:grid-cols-4'
    default:
      return 'grid-cols-1 md:grid-cols-2'
  }
}

export function editorSpanClass(columns: number | undefined): string {
  switch (normalizeColumns(columns)) {
    case 1:
      return ''
    case 4:
      return 'sm:[grid-column:var(--span-sm)] xl:[grid-column:var(--span)]'
    default:
      return 'md:[grid-column:var(--span)]'
  }
}

/**
 * Wide screens (web/docs/ui-style-contract.md, "Dashboard widgets"): once the
 * dashboard is 96rem wide (a 1920 px screen with the sidebar) the view lays
 * widgets on a 12-column grid and packs every run of side-by-side widgets
 * three to a row, and four to a row from 136rem (a 2560 px screen), so a wide
 * screen shows more widgets instead of two stretched ones. A run is a series
 * of neighbours with the same stored width that sit fewer to a row than that;
 * a full-width widget ends a run and stays full width. A run is split into
 * rows as evenly as it goes (four widgets three to a row are two rows of two,
 * never three and a lone one), so no row leaves an empty cell. Order is never
 * changed. The editor keeps the stored arrangement.
 */
export const WIDE_PACK_THREE_REM = 96
export const WIDE_PACK_FOUR_REM = 136

export interface WidePlacement {
  /** The widget's `grid-column` on the 12-column grid. */
  column: string
  /** Packed into a row of its run: one row tall (its stored height no longer places it). */
  packed: boolean
}

/** Where every widget sits on the 12-column grid, its runs packed `perRow` to a row. */
export function widePackSpans(
  widgets: ReadonlyArray<{ w: number }>,
  columns: number | undefined,
  perRow: number
): WidePlacement[] {
  const cols = normalizeColumns(columns)
  const spans = widgets.map((w) => colSpanFor(w.w, cols))
  const out: WidePlacement[] = spans.map((s) => ({
    column: gridColumnOf12((s * BASE_GRID) / cols),
    packed: false,
  }))
  if (cols === 1) return out
  let i = 0
  while (i < spans.length) {
    const s = spans[i]
    let j = i
    while (j < spans.length && spans[j] === s) j++
    const run = j - i
    // Full-width widgets, and runs already at least `perRow` to a row, keep their place.
    if (s < cols && cols / s < perRow && run > 1) {
      const rows = Math.ceil(run / perRow)
      const base = Math.floor(run / rows)
      const extra = run % rows
      let k = i
      for (let r = 0; r < rows; r++) {
        const inRow = base + (r < extra ? 1 : 0)
        for (let c = 0; c < inRow; c++) {
          out[k++] = { column: gridColumnOf12(BASE_GRID / inRow), packed: true }
        }
      }
    }
    i = j
  }
  return out
}

function gridColumnOf12(units: number): string {
  const u = Math.max(1, Math.min(BASE_GRID, Math.round(units)))
  return `span ${u} / span ${u}`
}

/** Grid classes of the wide 12-column layout (see `widePackSpans`). */
export const WIDE_GRID_CLASS = '@[96rem]:grid-cols-12'
/**
 * Widget classes of the wide layout. The spans arrive in `--span-wide` /
 * `--span-wider` and the row spans in `--row-span-wide` / `--row-span-wider`
 * (`auto` for a packed widget).
 */
export const WIDE_WIDGET_CLASS =
  '@[96rem]:[grid-column:var(--span-wide)] @[96rem]:[grid-row:var(--row-span-wide)] @[136rem]:[grid-column:var(--span-wider)] @[136rem]:[grid-row:var(--row-span-wider)]'
