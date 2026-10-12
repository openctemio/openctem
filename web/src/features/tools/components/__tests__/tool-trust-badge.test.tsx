import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'

import { ToolTrustBadge } from '../tool-availability'

/**
 * The trust and platform-assigned tier of a tool (RFC-055 §5): an
 * operator-installed copy is flagged unverified with its T2 tier, a built-in
 * tool shows its tier, and nothing shows without a contract.
 */
describe('ToolTrustBadge', () => {
  it('flags an unverified tool with its tier', () => {
    render(<ToolTrustBadge item={{ trust: 'unverified', tier: 'T2' }} />)
    const pill = screen.getByText('Unverified · T2')
    expect(pill.closest('[data-state]')?.getAttribute('data-state')).toBe('unverified')
    expect(pill.closest('[title]')?.getAttribute('title')).toMatch(/runs only as tier T2/)
  })

  it('shows the tier of a built-in tool', () => {
    render(<ToolTrustBadge item={{ trust: 'builtin', tier: 'T1' }} />)
    const pill = screen.getByText('T1')
    expect(pill.closest('[title]')?.getAttribute('title')).toMatch(
      /Built into the sensor.*T1 active/
    )
  })

  it('renders nothing without a contract', () => {
    const { container } = render(<ToolTrustBadge item={{}} />)
    expect(container).toBeEmptyDOMElement()
  })
})
