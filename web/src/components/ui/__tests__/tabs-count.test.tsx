import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { TabsCount } from '../tabs'

describe('TabsCount', () => {
  it('shows a locale-formatted number in a neutral pill', () => {
    render(<TabsCount value={12773} />)
    const el = screen.getByText((12773).toLocaleString())
    expect(el).toHaveAttribute('data-slot', 'tabs-count')
    expect(el).not.toHaveClass('text-destructive')
  })

  it('turns red for danger only while the count is positive', () => {
    const { rerender } = render(<TabsCount value={3} tone="danger" />)
    expect(screen.getByText('3')).toHaveClass('text-destructive')
    rerender(<TabsCount value={0} tone="danger" />)
    expect(screen.getByText('0')).not.toHaveClass('text-destructive')
  })

  it('shows a loading placeholder and renders nothing without a value', () => {
    const { container, rerender } = render(<TabsCount value="…" />)
    expect(screen.getByText('…')).toBeInTheDocument()
    rerender(<TabsCount value={undefined} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('keeps a one-digit pill while pending, hidden from screen readers', () => {
    const { container } = render(<TabsCount value={undefined} pending />)
    const pill = container.querySelector('[data-slot="tabs-count"]') as HTMLElement
    expect(pill).toHaveAttribute('data-pending')
    expect(pill).toHaveAttribute('aria-hidden')
    // The same box as a count (min-w-5, px-1.5) holding an invisible digit.
    expect(pill).toHaveClass('min-w-5', 'px-1.5', 'h-5')
    expect(pill.querySelector('.invisible')).toHaveTextContent('0')
  })
})
