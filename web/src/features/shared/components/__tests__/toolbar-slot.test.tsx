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
  it('is sized by every possible value, so a value or a late option never widens it', () => {
    render(
      <FilterSelect
        label="Practice"
        value="vulnerabilities"
        clearable={false}
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

  it('defaults to its options and All when it can be cleared', () => {
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
    const hidden = trigger.querySelectorAll('[data-slot="toolbar-slot"] > [aria-hidden="true"]')
    expect([...hidden].map((h) => h.getAttribute('data-label'))).toEqual(['All', 'Open', 'Closed'])
  })
})

describe('FilterSelect long value', () => {
  it('caps what the other values reserve, and lets the value shown size the token whole', () => {
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
    const slot = trigger.querySelector('[data-slot="toolbar-slot"]') as HTMLElement
    // The slot may grow to 15rem; the hidden options reserve at most 7rem.
    expect(slot).toHaveClass('max-w-60')
    for (const h of slot.querySelectorAll('[aria-hidden="true"]')) expect(h).toHaveClass('max-w-28')
    const value = slot.lastElementChild as HTMLElement
    expect(value).not.toHaveClass('w-0')
    expect(value).toHaveClass('truncate')
    expect(value).toHaveAttribute('title', 'Awaiting approval')
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
