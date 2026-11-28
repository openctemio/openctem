import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { CappedNotice } from '../capped-notice'

describe('CappedNotice', () => {
  it('says how many of the total are shown when the register was capped', () => {
    render(<CappedNotice loaded={1000} total={1500} />)
    expect(screen.getByRole('status')).toHaveTextContent(/first 1,?000 of 1,?500/)
  })

  it('links to the paginated list of every row when one is given', () => {
    render(<CappedNotice loaded={100} total={340} allHref="/assets?is_crown_jewel=true" />)
    expect(screen.getByRole('link', { name: /open all 340/i })).toHaveAttribute(
      'href',
      '/assets?is_crown_jewel=true'
    )
  })

  it('renders nothing when every row is loaded', () => {
    const { container } = render(<CappedNotice loaded={20} total={20} />)
    expect(container).toBeEmptyDOMElement()
  })
})
