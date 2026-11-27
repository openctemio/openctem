/**
 * The automatic phone card (a table without `mobileRow`, below 768px) chooses
 * its fields on fixed one-line rows, then shows them wrapping: a label is
 * never cut ("Hoạt động gần n…") and a value goes under its label and wraps
 * instead of ending in an ellipsis. Regression kept: a run's message beside
 * its state once wrapped in the few pixels the chip left and made the card
 * taller than the screen (/scans/runs at 390px, 2026-11-17); a row of a chip
 * and a text now wraps the text under the chip, and a text the table cuts on
 * one line takes at most three lines, then a clamp with the field's title.
 * Layout itself is measured by the e2e spec 66-phone-card-bounds; this pins
 * the rules the card applies.
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

const WRAP_RULES = [
  '[overflow-wrap:anywhere]',
  // A chip and a text in one row: the text wraps under the chip.
  '[&_.flex]:flex-wrap',
  // A text the table cuts on one line wraps, up to three lines.
  '[&_.truncate]:whitespace-normal',
  '[&_.truncate]:line-clamp-3',
]

describe('automatic phone card', () => {
  it('wraps a long value beside a chip, bounded, with its whole text as the title', () => {
    const message = 'Scan run completed partially: '.repeat(40)
    const { container } = render(
      <DataTable
        columns={columns}
        data={[{ id: '1', name: 'Weekly web scan', status: 'Partial', message }]}
        getRowId={(r) => r.id}
      />
    )
    const card = container.querySelector('[data-slot="mobile-card"]')
    expect(card).not.toBeNull()
    const field = card!.querySelector('[data-slot="mobile-card-field"]')!
    expect(field.className).toContain('flex-wrap')
    const value = field.querySelector('dd')!
    for (const rule of WRAP_RULES) expect(value.className).toContain(rule)
    expect(value.className).not.toContain('h-5')
    expect(value.className).not.toContain('whitespace-nowrap')
    // A clamped value says so and keeps its whole text reachable.
    expect(value).toHaveAttribute('data-cut-tooltip')
    expect(value.getAttribute('title')).toContain(message.trim())
    // The label wraps, never cut.
    const label = field.querySelector('dt')!
    expect(label.className).not.toContain('truncate')
    expect(label.className).toContain('break-words')
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
