/**
 * The automatic phone card has room for two fields. A list's key figures (a
 * count, a risk, a severity, a priority, a due date) take those places before
 * descriptive columns, whatever their column order. Regression (2026-11-18):
 * the asset groups card showed Criticality and Assets and left out
 * "Findings 0", the figure the list is about. The row's own state chip
 * (Criticality) stays on the title line beside the name, so nothing it showed
 * is lost; a status column the table drops on narrow screens (Environment)
 * gives it that place.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import type { ColumnDef } from '@tanstack/react-table'
import { DataTable } from '../data-table'

type Group = {
  id: string
  name: string
  environment: string
  criticality: string
  assets: number
  findings: number
  note: string
}

const columns: ColumnDef<Group>[] = [
  { accessorKey: 'name', header: 'Name', meta: { kind: 'name', label: 'Name' } },
  {
    accessorKey: 'environment',
    header: 'Environment',
    // The page lets a narrow table drop it, as on the asset groups list.
    meta: { kind: 'status', hideBelow: 760, label: 'Environment' },
  },
  {
    accessorKey: 'criticality',
    header: 'Criticality',
    meta: { kind: 'status', label: 'Criticality' },
  },
  { accessorKey: 'assets', header: 'Assets', meta: { kind: 'number', label: 'Assets' } },
  { accessorKey: 'findings', header: 'Findings', meta: { kind: 'number', label: 'Findings' } },
]

const row: Group = {
  id: '1',
  name: 'Payments',
  environment: 'Production',
  criticality: 'High',
  assets: 3,
  findings: 0,
  note: 'Synthetic',
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

describe('automatic phone card: key figures first', () => {
  it('gives the two field places to the counts, not to a status column before them', () => {
    const { container } = render(<DataTable columns={columns} data={[row]} />)
    expect(fieldLabels(container)).toEqual(['Assets', 'Findings'])
  })

  it('keeps a count of 0 (it is the figure, not an empty value)', () => {
    const { container } = render(<DataTable columns={columns} data={[row]} />)
    const findings = Array.from(
      container.querySelectorAll<HTMLElement>('[data-slot="mobile-card-field"]')
    ).find((f) => f.querySelector('dt')?.textContent === 'Findings')
    expect(findings?.querySelector('dd')?.textContent).toBe('0')
  })

  it('fills a place left by a figure with nothing to say from the other columns, in column order', () => {
    const text: ColumnDef<Group>[] = [
      ...columns.slice(0, 3),
      {
        id: 'assets',
        header: 'Assets',
        meta: { kind: 'number', label: 'Assets' },
        cell: () => <span>-</span>,
      },
      { accessorKey: 'note', header: 'Note', meta: { label: 'Note' } },
    ]
    const { container } = render(<DataTable columns={text} data={[row]} />)
    expect(fieldLabels(container)).toEqual(['Environment', 'Note'])
  })

  it('keeps the criticality chip on the title line, not a status the table drops', () => {
    const { container } = render(<DataTable columns={columns} data={[row]} />)
    const head = container.querySelector<HTMLElement>('[data-slot="mobile-card-head"]')!
    const status = head.querySelector<HTMLElement>('[data-slot="mobile-card-status"]')
    expect(status?.textContent).toBe('High')
    expect(fieldLabels(container)).not.toContain('Criticality')
  })

  it('takes the first status column when every one may be dropped', () => {
    const all = columns.map((c) =>
      (c.meta as { kind?: string } | undefined)?.kind === 'status'
        ? { ...c, meta: { ...c.meta, hideBelow: 900 } }
        : c
    )
    const { container } = render(<DataTable columns={all} data={[row]} />)
    expect(
      container.querySelector('[data-slot="mobile-card-head"] [data-slot="mobile-card-status"]')
        ?.textContent
    ).toBe('Production')
  })
})
