/**
 * Display > Columns names each column as its header reads, in the user's
 * language. It listed `meta.label` or else the raw column id, capitalised by
 * CSS: "asset name", "last_seen" read as English ids on a Vietnamese page
 * (acceptance review 2026-11-18).
 */
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '../data-table'
import { DataTableColumnHeader } from '../data-table-column-header'

type Row = { asset_name: string; last_seen: string; owner: string }

const columns: ColumnDef<Row>[] = [
  { accessorKey: 'owner', header: 'Chủ sở hữu', enableHiding: false },
  // A header component with a title, no meta.label.
  {
    accessorKey: 'asset_name',
    header: ({ column }) => <DataTableColumnHeader column={column} title="Tên tài sản" />,
  },
  // A plain string header, no meta.label.
  { accessorKey: 'last_seen', header: 'Lần thấy cuối' },
]

describe('DataTable Display > Columns labels', () => {
  it('lists each column by its header, never its id', async () => {
    render(
      <DataTable
        columns={columns}
        data={[{ asset_name: 'a', last_seen: 'b', owner: 'c' }]}
        mobileCards={false}
      />
    )
    await userEvent.click(screen.getByRole('button', { name: /display/i }))
    const items = (await screen.findAllByRole('menuitemcheckbox')).map((i) => i.textContent)
    expect(items).toEqual(['Tên tài sản', 'Lần thấy cuối'])
    for (const item of await screen.findAllByRole('menuitemcheckbox')) {
      expect(item.className).not.toContain('capitalize')
    }
  })
})
