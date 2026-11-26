/**
 * Only a row's name may end in an ellipsis (docs/ui-style-contract.md, "cut
 * meaning"). Final acceptance review (2026-11-25): phone cards cut plain
 * values and labels on a half line ("18 minutes a…", "Hoạt động gần n…").
 * A field whose value or label its half of the line cuts takes the whole
 * line, like a chip that does not fit.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '../data-table'

type Row = { id: string; name: string; seen: string; owner: string }

const columns = (seenLabel: string): ColumnDef<Row>[] => [
  { accessorKey: 'name', header: 'Name', meta: { kind: 'name', label: 'Name' } },
  {
    id: 'seen',
    header: seenLabel,
    meta: { label: seenLabel },
    cell: ({ row }) => <span>{row.original.seen}</span>,
  },
  {
    id: 'owner',
    header: 'Owner',
    meta: { label: 'Owner' },
    cell: ({ row }) => <span>{row.original.owner}</span>,
  },
]

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const setWidth = (value: number) =>
  Object.defineProperty(window, 'innerWidth', { configurable: true, value })

// jsdom has no layout: a label or value longer than 12 characters reports a
// content width wider than its half-line box.
const proto = HTMLElement.prototype
const saved = {
  scroll: Object.getOwnPropertyDescriptor(proto, 'scrollWidth'),
  client: Object.getOwnPropertyDescriptor(proto, 'clientWidth'),
}
const measured = (el: HTMLElement) => el.tagName === 'DD' || el.tagName === 'DT'

beforeEach(() => {
  setWidth(390)
  Object.defineProperty(proto, 'scrollWidth', {
    configurable: true,
    get(this: HTMLElement) {
      return measured(this) && (this.textContent ?? '').length > 12 ? 96 : 60
    },
  })
  Object.defineProperty(proto, 'clientWidth', {
    configurable: true,
    get(this: HTMLElement) {
      return measured(this) ? 72 : 0
    },
  })
})
afterEach(() => {
  setWidth(1440)
  if (saved.scroll) Object.defineProperty(proto, 'scrollWidth', saved.scroll)
  if (saved.client) Object.defineProperty(proto, 'clientWidth', saved.client)
})

const field = (container: HTMLElement, id: string) =>
  container.querySelector<HTMLElement>(`[data-slot="mobile-card-field"][data-column="${id}"]`)

describe('automatic phone card: plain values and labels are not cut', () => {
  it('gives a value that its half line cuts the whole line', () => {
    const { container } = render(
      <DataTable
        columns={columns('Seen')}
        data={[{ id: '1', name: 'web-01', seen: '18 minutes ago', owner: 'Ana' }]}
        getRowId={(r) => r.id}
      />
    )
    expect(field(container, 'seen')?.className).toContain('col-span-2')
    expect(field(container, 'owner')?.textContent).toContain('Ana')
  })

  it('gives a label that its half line cuts the whole line', () => {
    const { container } = render(
      <DataTable
        columns={columns('Hoạt động gần nhất')}
        data={[{ id: '1', name: 'web-01', seen: '3 phút', owner: 'Ana' }]}
        getRowId={(r) => r.id}
      />
    )
    expect(field(container, 'seen')?.className).toContain('col-span-2')
  })

  it('keeps two short fields on one line', () => {
    const { container } = render(
      <DataTable
        columns={columns('Seen')}
        data={[{ id: '1', name: 'web-01', seen: '3 min', owner: 'Ana' }]}
        getRowId={(r) => r.id}
      />
    )
    expect(field(container, 'seen')?.className).not.toContain('col-span-2')
    expect(field(container, 'owner')?.className).not.toContain('col-span-2')
    // Shown fields have no fixed line height: a longer value would wrap.
    expect(container.querySelector('[data-slot="mobile-card"] dl')?.className).not.toContain('h-5')
  })
})
