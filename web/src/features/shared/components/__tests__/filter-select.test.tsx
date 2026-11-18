import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FilterSelect } from '../filter-select'

const options = [
  { value: 'pending' as const, label: 'Pending', count: 3 },
  { value: 'approved' as const, label: 'Approved', count: 0 },
]

describe('FilterSelect', () => {
  it('reads as a filter token with the current value', () => {
    render(<FilterSelect label="Status" value="pending" options={options} onChange={() => {}} />)
    expect(screen.getByRole('button', { name: 'Status: Pending' })).toBeInTheDocument()
    expect(document.querySelector('[data-slot=filter-select]')).toHaveAttribute(
      'data-filtered',
      'true'
    )
  })

  it('clears back to every row', () => {
    const onChange = vi.fn()
    render(<FilterSelect label="Status" value="pending" options={options} onChange={onChange} />)
    fireEvent.click(screen.getByRole('button', { name: 'Clear Status' }))
    expect(onChange).toHaveBeenCalledWith('')
  })

  it('shows All and no clear button when nothing is filtered', () => {
    render(<FilterSelect label="Status" value="" options={options} onChange={() => {}} />)
    expect(screen.getByRole('button', { name: 'Status: All' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Clear Status' })).not.toBeInTheDocument()
  })

  it("keeps the clear button's room while nothing is filtered, so a value never resizes it", () => {
    const { rerender } = render(
      <FilterSelect label="Status" value="" options={options} onChange={() => {}} />
    )
    const room = document.querySelector('[data-slot=filter-select-clear-room]')
    expect(room).toHaveClass('size-7', 'me-1', 'shrink-0')
    expect(room).toHaveAttribute('aria-hidden')
    rerender(<FilterSelect label="Status" value="pending" options={options} onChange={() => {}} />)
    expect(document.querySelector('[data-slot=filter-select-clear-room]')).toBeNull()
    expect(document.querySelector('[data-slot=filter-select-clear]')).toHaveClass(
      'size-7',
      'me-1',
      'shrink-0'
    )
  })

  it('keeps no room for a clear button it never shows', () => {
    render(
      <FilterSelect
        label="Show"
        value="pending"
        options={options}
        clearable={false}
        onChange={() => {}}
      />
    )
    expect(document.querySelector('[data-slot=filter-select-clear-room]')).toBeNull()
  })

  it('lists every value with its count and picks one', async () => {
    const onChange = vi.fn()
    render(
      <FilterSelect label="Status" value="" options={options} allCount={3} onChange={onChange} />
    )
    await userEvent.click(screen.getByRole('button', { name: 'Status: All' }))
    const approved = await screen.findByRole('menuitemradio', { name: /Approved/ })
    expect(approved).toHaveTextContent('0')
    await userEvent.click(approved)
    expect(onChange).toHaveBeenCalledWith('approved')
  })

  it('always keeps a value when it is not clearable', async () => {
    render(
      <FilterSelect
        label="Show"
        value="pending"
        options={options}
        clearable={false}
        onChange={() => {}}
      />
    )
    expect(screen.queryByRole('button', { name: 'Clear Show' })).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Show: Pending' }))
    await screen.findByRole('menuitemradio', { name: /Approved/ })
    expect(screen.queryByRole('menuitemradio', { name: /^All/ })).not.toBeInTheDocument()
  })

  it('as a base chip folds its key on a narrow toolbar and keeps it in the name', () => {
    render(
      <FilterSelect
        label="Practice"
        value="pending"
        options={options}
        clearable={false}
        foldLabel
        onChange={() => {}}
      />
    )
    const trigger = screen.getByRole('button', { name: 'Practice: Pending' })
    expect(trigger.querySelector('span')).toHaveClass('@max-4xl/toolbar:hidden')
  })

  it('reads its fallback label when no value is chosen (a saved view sets it)', () => {
    render(
      <FilterSelect
        label="State"
        value=""
        allLabel="Set by the view"
        options={options}
        clearable={false}
        onChange={() => {}}
      />
    )
    expect(screen.getByRole('button', { name: 'State: Set by the view' })).toBeInTheDocument()
  })

  it('folded with nothing chosen shows its key instead of All, and keeps "State: All" as its name', () => {
    render(<FilterSelect label="State" value="" options={options} foldLabel onChange={() => {}} />)
    const trigger = screen.getByRole('button', { name: 'State: All' })
    const key = trigger.querySelector('[data-slot=filter-select-key]') as HTMLElement
    expect(key).toHaveTextContent('State')
    // Shown only while the key ("State:") is folded away, where "All" hides.
    expect(key).toHaveClass(
      'hidden',
      '@max-4xl/toolbar:inline',
      'group-data-[fold=true]/toolbar:inline'
    )
    expect(key.previousElementSibling).toHaveTextContent('All')
    expect(key.previousElementSibling).toHaveClass(
      '@max-4xl/toolbar:hidden',
      'group-data-[fold=true]/toolbar:hidden'
    )
    // The key sizes the slot too, so folding moves nothing.
    const sized = Array.from(trigger.querySelectorAll('[data-slot=toolbar-slot] [data-label]')).map(
      (el) => el.getAttribute('data-label')
    )
    expect(sized).toEqual(['All', 'Pending', 'Approved', 'State'])
  })

  it('folded with a chosen value shows the value', () => {
    render(
      <FilterSelect label="State" value="pending" options={options} foldLabel onChange={() => {}} />
    )
    const trigger = screen.getByRole('button', { name: 'State: Pending' })
    expect(trigger.querySelector('[data-slot=filter-select-key]')).toBeNull()
    expect(trigger.querySelector('[data-slot=toolbar-slot]')).toHaveTextContent('Pending')
  })

  it('the key never stands in without foldLabel, or for a select that always has a value', () => {
    const first = render(
      <FilterSelect label="State" value="" options={options} onChange={() => {}} />
    )
    expect(document.querySelector('[data-slot=filter-select-key]')).toBeNull()
    first.unmount()
    render(
      <FilterSelect
        label="State"
        value=""
        allLabel="Set by the view"
        options={options}
        clearable={false}
        foldLabel
        onChange={() => {}}
      />
    )
    expect(document.querySelector('[data-slot=filter-select-key]')).toBeNull()
    expect(document.querySelector('[data-slot=toolbar-slot] [data-label="State"]')).toBeNull()
  })
})
