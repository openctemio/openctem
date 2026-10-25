import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { NavCount } from '../nav-count'
import { NavBadge } from '../nav-group'

describe('NavCount', () => {
  it('renders a plain number, never a filled pill', () => {
    render(<NavCount>12</NavCount>)
    const el = screen.getByText('12')
    expect(el.className).toContain('text-muted-foreground')
    expect(el.className).not.toMatch(/\bbg-|rounded-full/)
  })

  it('marks a waiting queue with the act-here accent and a problem with the error colour', () => {
    render(
      <>
        <NavCount tone="action">2</NavCount>
        <NavCount tone="danger">5</NavCount>
      </>
    )
    expect(screen.getByText('2').className).toContain('text-signal-text')
    expect(screen.getByText('5').className).toContain('text-destructive')
  })

  it('is what a menu item count uses', () => {
    render(<NavBadge>3</NavBadge>)
    expect(screen.getByText('3').getAttribute('data-slot')).toBe('nav-count')
  })
})
