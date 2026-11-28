/**
 * Column definitions of the shared DataTable: what kind of value a column
 * holds decides its alignment, its width and its first sort direction, so a
 * page never styles a header or a cell itself. Spec of record:
 * docs/ui-style-contract.md, "Tables" (column kinds).
 */

import type { ReactNode } from 'react'

export type ColumnKind =
  | 'name'
  | 'id'
  | 'priority'
  | 'risk'
  | 'severity'
  | 'status'
  | 'status-edit'
  | 'asset'
  | 'owner'
  | 'datetime-recent'
  | 'date'
  | 'due'
  | 'number'
  | 'signals'
  | 'tags'
  | 'masked'
  | 'select'
  | 'actions'
  | 'decisions'
  | 'text'

export interface DataTableColumnMeta {
  /** What the column holds. Absent means `text` (pages still migrating). */
  kind?: ColumnKind
  /** Translated label: the header, the Columns menu and the phone card. */
  label?: string
  /** Fixed width in px (within the kind's range). */
  width?: number
  /** Narrowest the column may get, in px. */
  minWidth?: number
  /** Widest the column may get, in px; longer values end in an ellipsis. */
  maxWidth?: number
  /**
   * Freeze the column at the start while the table scrolls sideways (the
   * row's identifying columns). The table keeps the frozen group within a
   * share of its frame (`pinStartColumns`), so the scrolling part never
   * collapses. The row actions column is frozen at the end on its own.
   */
  pin?: 'start'
  /** Hide the column while the table frame is narrower than this (px). Kind sizing only. */
  hideBelow?: number
  /**
   * Content sizing (`columnSizing="content"`): the column may drop when the
   * frame cannot hold every column at its floor; 1 drops first, then 2, and
   * so on (replaces `hideBelow`, whose px points came from fixed widths).
   * The viewer's choice under Columns still wins.
   */
  dropOrder?: number
  /**
   * Why this column overrides its kind's sizing (`width`, `minWidth`,
   * `maxWidth`). Required on a content-sized table
   * (`column-width-override.test.ts`): widths follow the content unless a
   * measured reason says otherwise.
   */
  sizeReason?: string
  /** The direction of the first click on the header. */
  sortFirst?: 'asc' | 'desc'
  /** An info popover after the header label (legend, unit, scope). */
  headerHint?: ReactNode
  /**
   * The row's name when it is not the first column: gets the name floor and,
   * with no `kind` of its own, the name kind (sized by the room left, a long
   * title cut by its ellipsis instead of widening the table).
   */
  primary?: boolean
  /**
   * A key figure of the list although its kind is not one (e.g. a last-seen
   * time on a list of sessions): the automatic phone card shows it first.
   */
  cardFigure?: boolean
}

interface KindLayout {
  align: 'start' | 'end' | 'center'
  width?: number
  minWidth?: number
  maxWidth?: number
  sortFirst: 'asc' | 'desc'
}

/** Defaults per kind (alignment, widths in px, first sort direction). */
export const KIND_LAYOUT: Record<ColumnKind, KindLayout> = {
  // The name's floor is min(12rem, 36vw), set as a class (it depends on the viewport).
  name: { align: 'start', maxWidth: 520, sortFirst: 'asc' },
  id: { align: 'start', width: 120, sortFirst: 'asc' },
  priority: { align: 'start', width: 72, sortFirst: 'desc' },
  // The risk badge's longest text whole: "Not yet scored" ("Chưa được chấm điểm").
  risk: { align: 'start', width: 148, sortFirst: 'desc' },
  // The severity mark and its longest word whole: "Nghiêm trọng" (vi Critical).
  severity: { align: 'start', width: 128, sortFirst: 'desc' },
  status: { align: 'start', width: 128, sortFirst: 'asc' },
  'status-edit': { align: 'start', width: 140, sortFirst: 'asc' },
  asset: { align: 'start', minWidth: 200, maxWidth: 280, sortFirst: 'asc' },
  owner: { align: 'start', width: 160, sortFirst: 'asc' },
  // The longest relative time whole at 14px: "khoảng 11 tháng trước" (vi;
  // "about 11 months ago" in en) plus the cell padding. A longer one, or one
  // in a column a page made narrower, wraps between its words; the exact
  // time is in the <time> title.
  'datetime-recent': { align: 'end', width: 168, maxWidth: 168, sortFirst: 'desc' },
  // The longest date whole at 14px: "25 thg 11, 2026" (vi) plus the cell padding.
  date: { align: 'end', width: 124, sortFirst: 'desc' },
  // The SLA chip's longest text whole, never cut: "999+ d overdue" (128 with
  // the KEV mark; "Trễ 999+ ngày" 121) plus the cell padding.
  due: { align: 'start', width: 140, sortFirst: 'asc' },
  number: { align: 'end', minWidth: 72, maxWidth: 96, sortFirst: 'desc' },
  signals: { align: 'start', width: 140, sortFirst: 'desc' },
  tags: { align: 'start', minWidth: 160, maxWidth: 240, sortFirst: 'asc' },
  masked: { align: 'start', width: 200, sortFirst: 'asc' },
  select: { align: 'center', width: 40, sortFirst: 'asc' },
  actions: { align: 'center', width: 48, sortFirst: 'asc' },
  // A queue's decision buttons (Approve, Reject, More): end-aligned, as wide
  // as the page's buttons need (`width` from the page).
  decisions: { align: 'end', sortFirst: 'asc' },
  text: { align: 'start', sortFirst: 'asc' },
}

/** The kind of a column: its meta, a primary column `name`, else `select` / `actions` by id, else text. */
export function columnKind(id: string, meta: DataTableColumnMeta | undefined): ColumnKind {
  if (meta?.kind) return meta.kind
  if (meta?.primary) return 'name'
  if (id === 'select') return 'select'
  if (id === 'actions') return 'actions'
  return 'text'
}

export interface ColumnLayout {
  kind: ColumnKind
  align: 'start' | 'end' | 'center'
  sortFirst: 'asc' | 'desc'
  /** Inline style for the column's header and cells (widths only). */
  style: { width?: number; minWidth?: number; maxWidth?: number } | undefined
}

/** Alignment, width style and first sort direction of a column. */
export function columnLayout(id: string, meta: DataTableColumnMeta | undefined): ColumnLayout {
  const kind = columnKind(id, meta)
  const base = KIND_LAYOUT[kind]
  const width = meta?.width ?? base.width
  const minWidth = meta?.minWidth ?? width ?? base.minWidth
  const maxWidth = meta?.maxWidth ?? (meta?.width !== undefined ? width : (base.maxWidth ?? width))
  const style =
    width === undefined && minWidth === undefined && maxWidth === undefined
      ? undefined
      : {
          ...(width !== undefined ? { width } : {}),
          ...(minWidth !== undefined ? { minWidth } : {}),
          ...(maxWidth !== undefined ? { maxWidth } : {}),
        }
  return { kind, align: base.align, sortFirst: meta?.sortFirst ?? base.sortFirst, style }
}

/** `aria-sort` of a header: only the sorted column carries one. */
export function ariaSort(sorted: false | 'asc' | 'desc'): 'ascending' | 'descending' | undefined {
  if (sorted === 'asc') return 'ascending'
  if (sorted === 'desc') return 'descending'
  return undefined
}
