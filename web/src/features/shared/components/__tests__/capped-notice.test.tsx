import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { CappedNotice } from '../capped-notice'

describe('CappedNotice', () => {
  it('says how many of the total are shown when the register was capped', () => {
    render(<CappedNotice loaded={1000} total={1500} />)
    expect(screen.getByRole('status')).toHaveTextContent(/first 1,?000 of 1,?500/)
  })

  it('renders nothing when every row is loaded', () => {
    const { container } = render(<CappedNotice loaded={20} total={20} />)
    expect(container).toBeEmptyDOMElement()
  })
})
