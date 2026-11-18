/**
 * The automatic phone card (a table without `mobileRow`, below 768px) keeps
 * every line one line high: whatever a cell draws stays on one line, cut with
 * an ellipsis. Regression: a run's message beside its state wrapped in the
 * few pixels the chip left and made the card taller than the screen
 * (/scans/runs at 390px, 2026-11-17). Layout itself is measured by the e2e
 * spec 66-phone-card-bounds; this pins the rules the card applies.
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
    meta: { label: 'Status' },
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

const ONE_LINE_RULES = [
  'h-5',
  'overflow-hidden',
  'whitespace-nowrap',
  '[&_*]:whitespace-nowrap',
  '[&_.flex]:flex-nowrap',
  // A stacked cell lays its lines side by side instead of growing the card.
  '[&_.flex-col]:flex-row',
]

describe('automatic phone card', () => {
  it('keeps a long value beside a chip on one line of fixed height', () => {
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
    for (const rule of ONE_LINE_RULES) expect(value.className).toContain(rule)
    expect(value.className).not.toContain('line-clamp')
    // The title is the one line allowed to wrap: at most two lines, then cut.
    const title = card!.querySelector('[data-slot="mobile-card-title"]')!
    expect(title.className).toContain('max-h-10')
    expect(title.className).toContain('overflow-hidden')
    // Every field has a label and a value.
    const fields = card!.querySelectorAll('[data-slot="mobile-card-field"]')
    expect(fields).toHaveLength(1)
    expect(fields[0].querySelector('dt')?.textContent).toBe('Status')
    expect(fields[0].querySelector('dd')?.textContent).toContain('Partial')
  })
})
