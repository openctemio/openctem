/**
 * Every header cell and pager control has an accessible name: a column with no
 * visible header (row actions) names itself to screen readers, and the
 * rows-per-page select says what it sets.
 */
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '../data-table'

type Row = { name: string }
const columns: ColumnDef<Row>[] = [
  { accessorKey: 'name', header: 'Name' },
  { id: 'actions', cell: () => <button type="button">Open</button> },
]
const rows = Array.from({ length: 30 }, (_, i) => ({ name: `row ${i}` }))

describe('DataTable accessible names', () => {
  it('names a header-less actions column', () => {
    render(<DataTable columns={columns} data={rows} mobileCards={false} />)
    expect(screen.getByRole('columnheader', { name: 'Actions' })).toBeInTheDocument()
  })

  it('names the rows-per-page select with its value', () => {
    render(<DataTable columns={columns} data={rows} mobileCards={false} />)
    expect(screen.getByRole('combobox', { name: /Rows per page: \d+/ })).toBeInTheDocument()
  })
})
