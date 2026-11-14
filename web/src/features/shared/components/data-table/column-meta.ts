/**
 * Column definitions of the shared DataTable: what kind of value a column
 * holds decides its alignment, its width and its first sort direction, so a
 * page never styles a header or a cell itself. Spec of record:
 * docs/ui-style-contract.md, "Tables" (column kinds).
 */

import type { ReactNode } from 'react'
import type { RowData } from '@tanstack/react-table'

export type ColumnKind =
  | 'name'
  | 'id'
  | 'priority'
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
  /** Hide the column while the table frame is narrower than this (px). */
  hideBelow?: number
  /** The direction of the first click on the header. */
  sortFirst?: 'asc' | 'desc'
  /** An info popover after the header label (legend, unit, scope). */
  headerHint?: ReactNode
  /** The row's name when it is not the first column (gets the name floor). */
  primary?: boolean
}

declare module '@tanstack/react-table' {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars, @typescript-eslint/no-empty-object-type
  interface ColumnMeta<TData extends RowData, TValue> extends DataTableColumnMeta {}
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
  severity: { align: 'start', width: 96, sortFirst: 'desc' },
  status: { align: 'start', width: 128, sortFirst: 'asc' },
  'status-edit': { align: 'start', width: 140, sortFirst: 'asc' },
  asset: { align: 'start', minWidth: 200, maxWidth: 280, sortFirst: 'asc' },
  owner: { align: 'start', width: 160, sortFirst: 'asc' },
  'datetime-recent': { align: 'end', width: 104, sortFirst: 'desc' },
  date: { align: 'end', width: 112, sortFirst: 'desc' },
  due: { align: 'start', width: 112, sortFirst: 'asc' },
  number: { align: 'end', minWidth: 72, maxWidth: 96, sortFirst: 'desc' },
  signals: { align: 'start', width: 140, sortFirst: 'desc' },
  tags: { align: 'start', minWidth: 160, maxWidth: 240, sortFirst: 'asc' },
  masked: { align: 'start', width: 200, sortFirst: 'asc' },
  select: { align: 'center', width: 40, sortFirst: 'asc' },
  actions: { align: 'center', width: 48, sortFirst: 'asc' },
  text: { align: 'start', sortFirst: 'asc' },
}

/** The kind of a column: its meta, else `select` / `actions` by id, else text. */
export function columnKind(id: string, meta: DataTableColumnMeta | undefined): ColumnKind {
  if (meta?.kind) return meta.kind
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
