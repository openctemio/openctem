import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { DecorativeText } from '../decorative-text'

describe('DecorativeText', () => {
  it('draws its text with CSS, outside the accessible name and the text content', () => {
    render(
      <button type="button" aria-label="Search or go to">
        Search or go to
        <DecorativeText as="kbd" text="Ctrl K" />
      </button>
    )
    const button = screen.getByRole('button', { name: 'Search or go to' })
    // The visible label is the whole text content: the hint is not a text node.
    expect(button.textContent).toBe('Search or go to')
    const kbd = button.querySelector('kbd') as HTMLElement
    expect(kbd.getAttribute('data-text')).toBe('Ctrl K')
    expect(kbd.getAttribute('aria-hidden')).toBe('true')
    expect(kbd.className).toContain('before:content-[attr(data-text)]')
  })
})
