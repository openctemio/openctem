import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import { ListCount, ListTitleRow } from '../list-title-row'

describe('ListCount', () => {
  it('is one polite, atomic region read as the sentence the page gives', () => {
    render(<ListCount total={1234} label="1,234 findings" />)
    const count = screen.getByRole('status')
    expect(count).toHaveAttribute('data-slot', 'list-count')
    expect(count).toHaveAttribute('aria-live', 'polite')
    expect(count).toHaveAttribute('aria-atomic', 'true')
    expect(count).toHaveTextContent('1,234')
    expect(count.querySelector('.sr-only')).toHaveTextContent('1,234 findings')
  })

  it('shows a partial count with "+" and says so in its tooltip', () => {
    render(<ListCount total={1000} capped />)
    const count = screen.getByRole('status')
    expect(count).toHaveTextContent('1,000+')
    expect(count).toHaveAttribute('title', 'Counted up to this number')
  })

  it('keeps its place, empty, while the count is not known', () => {
    render(<ListCount total={0} loading label="0 findings" />)
    expect(screen.getByRole('status')).toBeEmptyDOMElement()
  })
})

describe('ListTitleRow', () => {
  it('puts the name and the count first, the list actions at the end', () => {
    render(
      <ListTitleRow title="All assets" count={<ListCount total={3} />}>
        <button type="button">Refresh</button>
      </ListTitleRow>
    )
    expect(screen.getByRole('heading', { level: 2, name: 'All assets' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Refresh' }).parentElement).toHaveClass('ms-auto')
  })
})
