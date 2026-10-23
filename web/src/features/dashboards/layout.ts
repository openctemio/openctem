/**
 * Shared layout constants for customizable dashboards (RFC-021).
 *
 * A dashboard renders as `columns` equal columns (1..4). Each widget stores its
 * width `w` on a 12-unit grid (so templates and older layouts keep working); at
 * render time that width is mapped to a column span of 1..columns. Rows have a
 * fixed pixel height so a short stat widget never balloons to fill space.
 */

/** Underlying grid the stored `w` is expressed in. */
export const BASE_GRID = 12

/** Default number of columns a dashboard is arranged in. */
export const DEFAULT_COLUMNS = 2

/** Fixed height (px) of one grid row. A widget of height `h` spans `h` rows. */
export const ROW_HEIGHT = 128

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
