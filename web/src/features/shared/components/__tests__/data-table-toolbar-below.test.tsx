import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ColumnDef } from '@tanstack/react-table'

import { DataTable } from '../data-table/data-table'

// Active context-filter chips go in a full-width row under the toolbar, never
// in the toolbar row: there a chip wrapped the start group onto a second line,
// the row grew and its end controls moved (owner report 2026-10-17).

type Row = { id: string; name: string }
const columns: ColumnDef<Row>[] = [{ accessorKey: 'name', header: 'Name' }]
const data: Row[] = [{ id: '1', name: 'edge-1' }]

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

describe('DataTable toolbarBelow', () => {
  it('renders the row directly under the toolbar, outside the toolbar row', () => {
    render(
      <DataTable
        columns={columns}
        data={data}
        showSearch={false}
        toolbarStart={<input aria-label="Search" />}
        toolbarEnd={<button type="button">Export</button>}
        toolbarBelow={<span data-testid="chip">Asset</span>}
      />
    )
    const below = screen.getByTestId('data-table-toolbar-below')
    expect(below.contains(screen.getByTestId('chip'))).toBe(true)
    const toolbar = below.previousElementSibling as HTMLElement
    expect(toolbar.contains(screen.getByLabelText('Search'))).toBe(true)
    expect(toolbar.contains(screen.getByRole('button', { name: 'Export' }))).toBe(true)
    expect(toolbar.contains(screen.getByTestId('chip'))).toBe(false)
  })

  it('reserves no row when there is nothing to show', () => {
    render(<DataTable columns={columns} data={data} showSearch={false} />)
    expect(screen.queryByTestId('data-table-toolbar-below')).toBeNull()
  })
})
