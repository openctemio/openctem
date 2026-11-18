/**
 * The automatic phone card (a table without `mobileRow`, below 768px) is a
 * compact card of fixed lines: the title line (title + status chip), one muted
 * subtitle line, and at most two fields that say something. Regressions from
 * the acceptance review (2026-11-18): a tall label-over-value grid, label rows
 * with an empty value or a lone dash, a field repeating the title (a name
 * column that falls back to the e-mail), and a later field ("Last seen")
 * dropped because the first columns were taken whether they held a value or
 * not.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '../data-table'

type Row = {
  id: string
  email: string
  name: string | null
  state: string
  role: string
  team: string | null
  device: string
  ip: string | null
  lastSeen: string
}

/** An unmarked column (no kind): always a labelled field, never the subtitle. */
const field = (id: keyof Row, label: string, empty: string): ColumnDef<Row> => ({
  id,
  header: label,
  meta: { label },
  cell: ({ row }) => <span className="truncate">{row.original[id] ?? empty}</span>,
})

const columns: ColumnDef<Row>[] = [
  { accessorKey: 'email', header: 'Member', meta: { kind: 'name', label: 'Member' } },
  // Falls back to the e-mail when the member has no display name.
  {
    id: 'name',
    header: 'Name',
    meta: { kind: 'owner', label: 'Name' },
    cell: ({ row }) => <span>{row.original.name ?? row.original.email}</span>,
  },
  {
    id: 'state',
    header: 'State',
    meta: { kind: 'status', label: 'State' },
    cell: ({ row }) => <span data-testid="chip">{row.original.state}</span>,
  },
  field('role', 'Role', ''),
  field('team', 'Team', '—'),
  field('device', 'Device', ''),
  field('ip', 'Address', '-'),
  field('lastSeen', 'Last seen', ''),
]

const base: Row = {
  id: '1',
  email: 'ana@example.com',
  name: 'Ana',
  state: 'Active',
  role: 'Admin',
  team: null,
  device: '',
  ip: null,
  lastSeen: '2 h ago',
}

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const setWidth = (value: number) =>
  Object.defineProperty(window, 'innerWidth', { configurable: true, value })

beforeEach(() => setWidth(390))
afterEach(() => setWidth(1440))

const fieldLabels = (container: HTMLElement) =>
  Array.from(container.querySelectorAll<HTMLElement>('[data-slot="mobile-card-field"]')).map(
    (f) => f.querySelector('dt')?.textContent
  )

const slot = (container: HTMLElement, name: string) =>
  container.querySelector<HTMLElement>(`[data-slot="mobile-card-${name}"]`)

describe('automatic phone card: compact lines', () => {
  it('puts the status chip on the title line and the naming column on the subtitle line', () => {
    const { container } = render(
      <DataTable columns={columns} data={[base]} getRowId={(r) => r.id} />
    )
    expect(slot(container, 'title')?.textContent).toBe('ana@example.com')
    expect(slot(container, 'status')?.textContent).toBe('Active')
    const subtitle = slot(container, 'subtitle')
    expect(subtitle?.textContent).toBe('Ana')
    expect(subtitle?.className).toContain('text-muted-foreground')
    // Neither is repeated as a labelled field.
    expect(fieldLabels(container)).not.toContain('State')
    expect(fieldLabels(container)).not.toContain('Name')
  })

  it('leaves out empty and dash-only values and keeps a later field', () => {
    const { container } = render(
      <DataTable columns={columns} data={[base]} getRowId={(r) => r.id} />
    )
    expect(fieldLabels(container)).toEqual(['Role', 'Last seen'])
  })

  it('shows at most two fields, the first ones with a value', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={[{ ...base, team: 'Blue', device: 'laptop', ip: '10.0.0.1' }]}
        getRowId={(r) => r.id}
      />
    )
    expect(fieldLabels(container)).toEqual(['Role', 'Team'])
  })

  it('keeps the subtitle line empty, at its height, when it repeats the title', () => {
    const { container } = render(
      <DataTable columns={columns} data={[{ ...base, name: null }]} getRowId={(r) => r.id} />
    )
    const subtitle = slot(container, 'subtitle')!
    expect(subtitle.className).toContain('invisible')
    expect(subtitle.className).toContain('h-5')
    expect(subtitle).toHaveAttribute('aria-hidden', 'true')
  })

  it('keeps the field line, with no label, when no field says anything', () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={[{ ...base, role: '', lastSeen: '' }]}
        getRowId={(r) => r.id}
      />
    )
    expect(fieldLabels(container)).toEqual([])
    expect(container.querySelector('[data-slot="mobile-card"] dl')?.className).toContain('h-5')
  })

  it('never makes an unmarked column the subtitle', () => {
    const { container } = render(
      <DataTable
        columns={[columns[0], field('role', 'Role', '')]}
        data={[base]}
        getRowId={(r) => r.id}
      />
    )
    expect(slot(container, 'subtitle')).toBeNull()
    expect(fieldLabels(container)).toEqual(['Role'])
  })
})
