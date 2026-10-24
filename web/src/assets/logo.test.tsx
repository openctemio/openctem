import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Logo, LogoFull } from './logo'

describe('LogoFull', () => {
  it('renders the wordmark as outlined paths, never as font-dependent text', () => {
    const { container } = render(<LogoFull />)
    const svg = screen.getByRole('img', { name: 'OpenCTEM' })

    // A <text> element is drawn with whatever font the OS has; on a Linux
    // desktop without the requested fonts the letters overlapped the C.
    expect(container.querySelector('text')).toBeNull()
    expect(container.innerHTML).not.toMatch(/font-family|fontFamily/i)

    for (const id of ['wordmark-open', 'wordmark-tem']) {
      const path = screen.getByTestId(id)
      expect(path.tagName.toLowerCase()).toBe('path')
      expect(path.getAttribute('d')?.length ?? 0).toBeGreaterThan(200)
      expect(path.getAttribute('fill')).toBe('currentColor')
    }
    expect(svg.getAttribute('viewBox')).toBe('0 0 278 61')
  })

  it('sets the C as a capital: on the baseline, up to cap height, with overshoot', () => {
    // Inter Bold at 56 units in this box: cap height y=4.7, baseline y=45.4.
    // A round capital overshoots both lines by about 1.5 percent; it must
    // never hang below the baseline the way the old scaled mark did.
    const { container } = render(<LogoFull />)
    const c = screen.getByTestId('wordmark-c')
    // d = "M x y1 A r r 0 1 0 x y2"
    const n = (c.getAttribute('d') ?? '').match(/-?\d+(\.\d+)?/g)!.map(Number)
    const [y1, r, y2] = [n[1], n[2], n[8]]
    const sw = Number(c.getAttribute('stroke-width'))
    const cy = (y1 + y2) / 2
    const outerTop = cy - r - sw / 2
    const outerBottom = cy + r + sw / 2
    expect(outerBottom).toBeGreaterThan(45.4)
    expect(outerBottom).toBeLessThan(46.5)
    expect(outerTop).toBeGreaterThan(3.5)
    expect(outerTop).toBeLessThan(4.7)
    // The marker sits in the C's opening at the C's vertical centre.
    expect(Number(container.querySelector('circle')?.getAttribute('cy'))).toBeCloseTo(cy, 1)
    expect(container.querySelector('[transform]')).toBeNull()
  })

  it('keeps the accent marker colour configurable', () => {
    const { container } = render(<LogoFull markerColor="#123456" />)
    expect(container.querySelector('circle')?.getAttribute('fill')).toBe('#123456')
  })

  it('passes className through', () => {
    render(<LogoFull className="h-12" />)
    expect(screen.getByRole('img', { name: 'OpenCTEM' }).getAttribute('class')).toContain('h-12')
  })
})

describe('Logo', () => {
  it('renders the mark without text', () => {
    const { container } = render(<Logo />)
    expect(screen.getByRole('img', { name: 'OpenCTEM' })).toBeTruthy()
    expect(container.querySelector('text')).toBeNull()
  })
})
