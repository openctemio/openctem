import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { PossiblePathLabel } from '../possible-path-label'

describe('PossiblePathLabel', () => {
  it('says the path is possible, not proven, and why, also to screen readers', () => {
    render(<PossiblePathLabel />)
    const label = screen.getByText('Possible path, not proven')
    const badge = label.closest('[data-slot="possible-path"]')
    expect(badge).not.toBeNull()
    expect(badge?.getAttribute('title')).toMatch(
      /No check has shown that an attacker can follow it/
    )
    expect(badge?.textContent).toMatch(/asset relationships and open findings/)
  })
})
