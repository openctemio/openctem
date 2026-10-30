import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Logo, LogoFull, LogoStacked, LogoWordmark } from './logo'

describe('LogoFull', () => {
  it('renders outlined paths, never font-dependent text', () => {
    const { container } = render(<LogoFull />)
    const svg = screen.getByRole('img', { name: 'OpenCTEM' })
    expect(svg.getAttribute('data-testid')).toBe('logo-full')

    // A <text> element is drawn with whatever font the OS has.
    expect(container.querySelector('text')).toBeNull()
    expect(container.innerHTML).not.toMatch(/font-family|fontFamily/i)

    const word = [...container.querySelectorAll('path')].find(
      (p) => (p.getAttribute('d')?.length ?? 0) > 1000
    )
    expect(word?.getAttribute('fill')).toBe('currentColor')
    // Horizontal lockup is 6.5:1.
    const [, , w, h] = svg.getAttribute('viewBox')!.split(' ').map(Number)
    expect(w / h).toBeCloseTo(6.5, 1)
  })

  it('draws the marker in the brand token, and only the marker', () => {
    const { container } = render(<LogoFull />)
    const rects = container.querySelectorAll('rect')
    expect(rects).toHaveLength(1)
    expect(rects[0].getAttribute('fill')).toBe('var(--brand)')
    expect(container.innerHTML).not.toMatch(/#[0-9a-f]{6}/i)
  })

  it('keeps the accent marker colour configurable', () => {
    const { container } = render(<LogoFull markerColor="#123456" />)
    expect(container.querySelector('rect')?.getAttribute('fill')).toBe('#123456')
  })

  it('passes className through', () => {
    render(<LogoFull className="h-12" />)
    expect(screen.getByRole('img', { name: 'OpenCTEM' }).getAttribute('class')).toContain('h-12')
  })
})

describe('LogoWordmark and LogoStacked', () => {
  it('are named OpenCTEM and carry the outlined wordmark', () => {
    const { container } = render(
      <>
        <LogoWordmark />
        <LogoStacked />
      </>
    )
    expect(screen.getAllByRole('img', { name: 'OpenCTEM' })).toHaveLength(2)
    expect(screen.getByTestId('logo-wordmark')).toBeTruthy()
    expect(screen.getByTestId('logo-stacked')).toBeTruthy()
    expect(container.querySelector('text')).toBeNull()
  })
})

describe('Logo (symbol)', () => {
  const cut = (size?: number) => {
    const { container, unmount } = render(<Logo size={size} />)
    const svg = container.querySelector('svg')!
    const result = svg.getAttribute('data-cut')
    unmount()
    return result
  }

  it('uses the 16 px cut at 24 px or less, the 32 px cut up to 40 px, the master above', () => {
    expect(cut(16)).toBe('16')
    expect(cut(24)).toBe('16')
    expect(cut()).toBe('16')
    expect(cut(28)).toBe('32')
    expect(cut(32)).toBe('32')
    expect(cut(40)).toBe('32')
    expect(cut(48)).toBe('master')
  })

  it('is named OpenCTEM, has no text, and one marker square', () => {
    const { container } = render(<Logo size={48} />)
    expect(screen.getByRole('img', { name: 'OpenCTEM' })).toBeTruthy()
    expect(screen.getByTestId('logo-symbol')).toBeTruthy()
    expect(container.querySelector('text')).toBeNull()
    expect(container.querySelectorAll('rect')).toHaveLength(1)
  })

  it('draws the small cuts on whole pixels', () => {
    const { container } = render(<Logo size={16} />)
    expect(container.querySelector('path')?.getAttribute('d')).toBe('M3 7V3h4M13 9V13H9')
    const marker = container.querySelector('rect')!
    expect(['x', 'y', 'width', 'height'].map((a) => Number(marker.getAttribute(a)))).toEqual([
      8, 4, 4, 4,
    ])
  })
})
