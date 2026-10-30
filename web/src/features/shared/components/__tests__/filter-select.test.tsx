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
})
