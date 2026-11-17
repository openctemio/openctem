/**
 * The automatic phone card (a table without `mobileRow`, below 768px) lets a
 * cell's one-line text wrap, but never into a tall sliver: a cut text stops at
 * three lines and the cell's flex row wraps, so a long text moves under the
 * chip beside it. Regression: a run's message beside its state wrapped in the
 * few pixels the chip left and made the card taller than the screen
 * (/scans/runs at 390px, 2026-11-17). Layout itself is measured by the e2e
 * spec 63-phone-card-bounds; this pins the rules the card applies.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '../data-table'

type Row = { id: string; name: string; status: string; message: string }

const columns: ColumnDef<Row>[] = [
  { accessorKey: 'name', header: 'Name', meta: { kind: 'name', label: 'Name' } },
  {
    id: 'status',
    header: 'Status',
    meta: { kind: 'text', label: 'Status' },
    cell: ({ row }) => (
      <div className="flex min-w-0 items-center gap-2">
        <span data-testid="chip" className="shrink-0 whitespace-nowrap">
          {row.original.status}
        </span>
        <span data-testid="message" className="min-w-0 truncate">
          {row.original.message}
        </span>
      </div>
    ),
  },
]

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const setWidth = (value: number) =>
  Object.defineProperty(window, 'innerWidth', { configurable: true, value })

beforeEach(() => setWidth(390))
afterEach(() => setWidth(1440))

const WRAP_RULES = [
  '[&_.truncate]:whitespace-normal',
  '[&_.truncate]:line-clamp-3',
  '[&_.whitespace-nowrap]:whitespace-normal',
  // Rows only: a wrapping column would size its items past the field.
  '[&_.flex:not(.flex-col)]:flex-wrap',
]

describe('automatic phone card', () => {
  it('wraps a field value by rule: cut texts stop at three lines, flex rows wrap', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={[
          {
            id: '1',
            name: 'Weekly web scan',
            status: 'Partial',
            message: 'Scan run completed partially: '.repeat(40),
          },
        ]}
        getRowId={(r) => r.id}
      />
    )
    const card = container.querySelector('[data-slot="mobile-card"]')
    expect(card).not.toBeNull()
    const value = card!.querySelector('[data-slot="mobile-card-field"] dd')!
    for (const rule of WRAP_RULES) expect(value.className).toContain(rule)
    // The title follows the same rules.
    const title = card!.querySelector('.flex-\\[1_1_60\\%\\]')!
    for (const rule of WRAP_RULES) expect(title.className).toContain(rule)
    // Every field has a label and a value.
    const fields = card!.querySelectorAll('[data-slot="mobile-card-field"]')
    expect(fields).toHaveLength(1)
    expect(fields[0].querySelector('dt')?.textContent).toBe('Status')
    expect(fields[0].querySelector('dd')?.textContent).toContain('Partial')
  })
})
