/**
 * A list with no rows shows its empty state alone: no column headers and no
 * select-all box over nothing (acceptance review 2026-11-18: every bulk list
 * in its 0-row state kept the header row and an unchecked select-all box).
 * While loading the header stays, so the skeleton rows sit under it.
 */
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '../data-table'

type Row = { id: string; name: string }
const columns: ColumnDef<Row>[] = [{ accessorKey: 'name', header: 'Name' }]
const bulk = { rowLabel: (r: Row) => r.name, actions: null }

describe('DataTable with no rows', () => {
  it('draws no header row and no select-all box', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={[]}
        mobileCards={false}
        bulk={bulk}
        emptyMessage="Nothing yet"
      />
    )
    expect(screen.getByText('Nothing yet')).toBeInTheDocument()
    expect(container.querySelector('thead')).toBeNull()
    expect(container.querySelector('thead [role=checkbox]')).toBeNull()
  })

  it('keeps the header while loading and once rows arrive', () => {
    const { container, rerender } = render(
      <DataTable columns={columns} data={[]} mobileCards={false} isLoading />
    )
    expect(container.querySelector('thead')).not.toBeNull()
    rerender(<DataTable columns={columns} data={[{ id: '1', name: 'a' }]} mobileCards={false} />)
    expect(screen.getByRole('columnheader', { name: 'Name' })).toBeInTheDocument()
  })
})
