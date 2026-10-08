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
    expect(svg.getAttribute('viewBox')).toBe('0 0 304 92')
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
