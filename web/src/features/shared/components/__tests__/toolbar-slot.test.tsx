import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import { ToolbarSlot } from '../toolbar-slot'
import { FilterSelect } from '../filter-select'

describe('ToolbarSlot', () => {
  it('lays every option out hidden in one cell, the value on top without a width of its own', () => {
    const { container } = render(
      <ToolbarSlot options={['Group', 'Asset owner', 'Severity']} title="Severity">
        Severity
      </ToolbarSlot>
    )
    const slot = container.querySelector('[data-slot="toolbar-slot"]') as HTMLElement
    expect(slot).toHaveClass('inline-grid', 'grid-cols-[minmax(0,1fr)]')
    const hidden = slot.querySelectorAll('[aria-hidden="true"]')
    expect([...hidden].map((h) => h.getAttribute('data-label'))).toEqual([
      'Group',
      'Asset owner',
      'Severity',
    ])
    // Generated content, not page text: the value is the only text.
    for (const h of hidden) expect(h).toBeEmptyDOMElement()
    expect(slot).toHaveTextContent(/^Severity$/)
    for (const h of hidden) expect(h).toHaveClass('invisible', 'col-start-1', 'row-start-1')
    // The value takes no width (w-0) and fills the cell (min-w-full): it can
    // never widen the slot, and a longer one is cut with its full title.
    const value = slot.lastElementChild as HTMLElement
    expect(value).toHaveClass('w-0', 'min-w-full', 'truncate', 'col-start-1', 'row-start-1')
    expect(value).toHaveAttribute('title', 'Severity')
  })
})

describe('FilterSelect width', () => {
  it('with holdWidth is sized by every possible value, so a value or a late option never widens it', () => {
    render(
      <FilterSelect
        label="Practice"
        value="vulnerabilities"
        clearable={false}
        holdWidth
        options={[{ value: 'vulnerabilities', label: 'Vulnerabilities' }]}
        sizeLabels={['Vulnerabilities', 'Compliance', 'Pentest and bug bounty']}
        onChange={() => {}}
      />
    )
    const trigger = screen.getByRole('button', { name: 'Practice: Vulnerabilities' })
    const hidden = trigger.querySelectorAll('[data-slot="toolbar-slot"] > [aria-hidden="true"]')
    expect([...hidden].map((h) => h.getAttribute('data-label'))).toEqual([
      'Vulnerabilities',
      'Compliance',
      'Pentest and bug bounty',
    ])
  })

  it('without holdWidth hugs the value shown: no box reserved for the others', () => {
    render(
      <FilterSelect
        label="Status"
        value=""
        options={[
          { value: 'open', label: 'Open' },
          { value: 'closed', label: 'Closed' },
        ]}
        onChange={() => {}}
      />
    )
    const trigger = screen.getByRole('button', { name: 'Status: All' })
    expect(trigger.querySelector('[data-slot="toolbar-slot"]')).toBeNull()
    expect(trigger.querySelector('[data-slot="filter-select-value"]')).toHaveTextContent('All')
  })
})

describe('FilterSelect long value', () => {
  it('shows a long value whole up to 15rem, then cuts it with its full text as the title', () => {
    render(
      <FilterSelect
        label="Status"
        value="pending"
        options={[
          { value: 'pending', label: 'Awaiting approval' },
          { value: 'approved', label: 'Approved' },
        ]}
        onChange={() => {}}
      />
    )
    const trigger = screen.getByRole('button', { name: 'Status: Awaiting approval' })
    const value = trigger.querySelector('[data-slot="filter-select-value"]') as HTMLElement
    expect(value).toHaveClass('max-w-60', 'truncate', 'min-w-0')
    expect(value).toHaveAttribute('title', 'Awaiting approval')
    expect(value).toHaveAttribute('data-cut-tooltip')
  })

  it('holdWidth keeps one width: the value never sizes the token and is cut instead', () => {
    render(
      <FilterSelect
        label="State"
        value=""
        allLabel="Set by the view"
        clearable={false}
        holdWidth
        options={[
          { value: 'open', label: 'Open' },
          { value: 'closed', label: 'Closed' },
        ]}
        onChange={() => {}}
      />
    )
    const trigger = screen.getByRole('button', { name: 'State: Set by the view' })
    const slot = trigger.querySelector('[data-slot="toolbar-slot"]') as HTMLElement
    expect(slot).toHaveClass('max-w-28')
    expect(slot).not.toHaveClass('max-w-60')
    const value = slot.lastElementChild as HTMLElement
    expect(value).toHaveClass('w-0', 'min-w-full', 'truncate')
    expect(value).toHaveAttribute('title', 'Set by the view')
  })
})
