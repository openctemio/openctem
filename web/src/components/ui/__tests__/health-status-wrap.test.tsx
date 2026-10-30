import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ColumnDef } from '@tanstack/react-table'

import { HealthStatus } from '../health-status'
import { RunStatusBadge } from '@/features/shared/components/run-status-badge'
import { DataTable } from '@/features/shared/components/data-table/data-table'

/**
 * A state with a detail ("Partial 9 unreachable, 373 skipped") must fit a
 * narrow box: the state stays one chip on one line, and the detail is muted
 * text beside it that drops to the next line and wraps when the box is too
 * narrow (owner report 2026-10-30: a phone run card ran the note into the next
 * column). jsdom has no layout, so these pin the structure and classes that
 * make it wrap; e2e/specs/49-phone-card-fields.spec.ts measures it in a browser.
 */
describe('HealthStatus with a detail', () => {
  it('keeps the chip to the state and puts the detail beside it, wrappable', () => {
    const { container } = render(
      <HealthStatus state="warn" label="Partial" detail={['9 unreachable', '373 skipped']} />
    )
    const chip = container.querySelector('[data-slot="health-status"]') as HTMLElement
    expect(chip.textContent).toBe('Partial')
    expect(chip.className).toContain('whitespace-nowrap')

    const line = container.querySelector('[data-slot="health-status-line"]') as HTMLElement
    expect(line).toContainElement(chip)
    // The line wraps between the chip and the detail, and never grows past its box.
    expect(line.className).toContain('flex-wrap')
    expect(line.className).toContain('max-w-full')

    const detail = screen.getByText('9 unreachable')
    expect(chip).not.toContainElement(detail)
    expect(detail.className).not.toContain('whitespace-nowrap')
    expect(detail.className).toContain('break-words')
  })

  it('without a detail stays a single element, as before', () => {
    const { container } = render(<HealthStatus state="ok" label="Completed" />)
    expect(container.querySelector('[data-slot="health-status-line"]')).toBeNull()
    expect(container.firstElementChild?.getAttribute('data-slot')).toBe('health-status')
  })

  it('icon only folds the detail into the label, with no line around it', () => {
    const { container } = render(
      <HealthStatus state="warn" label="Partial" detail="3 unreachable" iconOnly />
    )
    expect(container.querySelector('[data-slot="health-status-line"]')).toBeNull()
    expect(container.querySelector('[data-slot="health-status"]')?.getAttribute('aria-label')).toBe(
      'Partial, 3 unreachable'
    )
  })

  it('a run note stays outside the state chip', () => {
    const { container } = render(
      <RunStatusBadge status="partial" note="9 unreachable, 373 skipped" />
    )
    const chip = container.querySelector('[data-slot="health-status"]') as HTMLElement
    expect(chip.getAttribute('data-health')).toBe('warn')
    expect(chip.textContent).not.toContain('unreachable')
    expect(screen.getByText('9 unreachable, 373 skipped')).toBeInTheDocument()
  })
})

type Row = { id: string; name: string; status: string; tasks: string }

describe('DataTable phone card fields', () => {
  it('let nowrap content in a field wrap inside its column', () => {
    Object.defineProperty(window, 'innerWidth', { configurable: true, value: 390 })
    const columns: ColumnDef<Row>[] = [
      { accessorKey: 'name', header: 'Name' },
      {
        accessorKey: 'status',
        header: 'Status',
        cell: () => <RunStatusBadge status="partial" note="9 unreachable, 373 skipped" />,
      },
      { accessorKey: 'tasks', header: 'Tasks' },
    ]
    render(
      <DataTable
        columns={columns}
        data={[{ id: '1', name: 'Run', status: 'partial', tasks: '31/42 tasks' }]}
        showSearch={false}
        showPagination={false}
      />
    )
    const card = document.querySelector('[data-slot="mobile-card"]') as HTMLElement
    expect(card).not.toBeNull()
    const fields = card.querySelectorAll('[data-slot="mobile-card-field"]')
    expect(fields).toHaveLength(2)
    const value = fields[0].querySelector('dd') as HTMLElement
    expect(value.textContent).toContain('9 unreachable, 373 skipped')
    // Same relaxation as the card title: nothing in a field may refuse to wrap.
    expect(value.className).toContain('[&_.whitespace-nowrap]:whitespace-normal')
    expect(value.className).toContain('[&_.truncate]:whitespace-normal')
    expect(value.className).toContain('min-w-0')
  })
})
