/**
 * A name column is sized by its floor and the room left, never by its text:
 * a long task or campaign title is cut by its ellipsis instead of widening the
 * table past its frame (acceptance 3: the Deadline and Due columns of
 * /remediation/tasks and /remediation/campaigns were cut at 1440 px).
 */
import { describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '../data-table'

type Row = { id: string; name: string }
const columns: ColumnDef<Row>[] = [
  { accessorKey: 'name', header: 'Name', meta: { kind: 'name', label: 'Name' } },
]

describe('DataTable name column', () => {
  it('is sized by its floor even without meta.minWidth', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={[{ id: '1', name: 'x'.repeat(200) }]}
        getRowId={(r) => r.id}
      />
    )
    const cell = container.querySelector('tbody td') as HTMLElement
    expect(cell.className).toContain('[contain:inline-size]')
  })
})
