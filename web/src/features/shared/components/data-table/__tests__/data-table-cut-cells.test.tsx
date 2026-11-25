/**
 * A cell that can be too wide for its column (a due date with a mark, a task
 * count) ends in an ellipsis, never a hard clip.
 */
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '../data-table'

type Row = { id: string; name: string; due: string; owner: string }
const columns: ColumnDef<Row>[] = [
  { accessorKey: 'name', header: 'Name', meta: { kind: 'name', label: 'Name' } },
  { accessorKey: 'due', header: 'Due', meta: { kind: 'due', label: 'Due' } },
  {
    accessorKey: 'owner',
    header: 'Owner',
    meta: { kind: 'owner', label: 'Owner', hideBelow: 5000 },
  },
]
const rows: Row[] = [{ id: '1', name: 'alpha', due: 'Apr 29, 2026, 23 d overdue', owner: 'Sam' }]

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

function renderTable() {
  return render(
    <DataTable
      columns={columns}
      data={rows}
      getRowId={(r) => r.id}
      pagination={{ pageIndex: 0, pageSize: 25 }}
      onPaginationChange={() => {}}
    />
  )
}

describe('DataTable cut cells', () => {
  it('ends a fixed-width cell in an ellipsis instead of clipping it', () => {
    renderTable()
    const cell = screen.getAllByText('Apr 29, 2026, 23 d overdue')[0].closest('td')!
    expect(cell.className).toContain('overflow-hidden')
    expect(cell.className).toContain('text-ellipsis')
  })

  it('does not put the ellipsis on the name cell, which truncates its own link', () => {
    renderTable()
    const cell = screen.getAllByText('alpha')[0].closest('td')!
    expect(cell.className).not.toContain('text-ellipsis')
  })

  it('never cuts a column header: a long label wraps', () => {
    renderTable()
    const head = screen.getAllByText('Due')[0].closest('th')!
    expect(head.className).not.toContain('text-ellipsis')
    expect(head.className).toContain('whitespace-normal')
    expect(head.className).not.toContain('whitespace-nowrap')
  })

  it('keeps a date on one line but lets a relative time wrap', () => {
    const timed: ColumnDef<Row>[] = [
      columns[0],
      { accessorKey: 'due', header: 'Created', meta: { kind: 'date', label: 'Created' } },
      { accessorKey: 'owner', header: 'Seen', meta: { kind: 'datetime-recent', label: 'Seen' } },
    ]
    render(
      <DataTable
        columns={timed}
        data={rows}
        getRowId={(r) => r.id}
        pagination={{ pageIndex: 0, pageSize: 25 }}
        onPaginationChange={() => {}}
      />
    )
    const date = screen.getAllByText('Apr 29, 2026, 23 d overdue')[0].closest('td')!
    const seen = screen.getAllByText('Sam')[0].closest('td')!
    expect(date.className).toContain('whitespace-nowrap')
    expect(seen.className).not.toContain('whitespace-nowrap')
  })

  it('lets an owner wrap ("Chưa có chủ sở hữu") instead of ending in an ellipsis', () => {
    renderTable()
    const owner = screen.getAllByText('Sam')[0].closest('td')!
    expect(owner).toHaveAttribute('data-column-kind', 'owner')
    expect(owner.className).toContain('whitespace-normal')
  })

  it('leaves a pinned cell unclipped so its edge shadow stays visible', () => {
    const pinned: ColumnDef<Row>[] = [
      { accessorKey: 'name', header: 'Name', meta: { kind: 'asset', pin: 'start', label: 'Name' } },
      ...columns.slice(1),
    ]
    render(
      <DataTable
        columns={pinned}
        data={rows}
        getRowId={(r) => r.id}
        pagination={{ pageIndex: 0, pageSize: 25 }}
        onPaginationChange={() => {}}
      />
    )
    const cell = screen.getAllByText('alpha')[0].closest('td')!
    expect(cell.className).toContain('sticky')
    expect(cell.className).not.toContain('overflow-hidden')
  })
})
