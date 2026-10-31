import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { FullscreenToggle } from '../fullscreen-toggle'

describe('FullscreenToggle', () => {
  it('is hidden below the md breakpoint (phones) where the API is available', () => {
    Object.defineProperty(document, 'fullscreenEnabled', { value: true, configurable: true })
    render(<FullscreenToggle />)
    const button = screen.getByRole('button', { name: 'Full screen' })
    expect(button.className).toMatch(/(^|\s)hidden(\s|$)/)
    expect(button.className).toContain('md:inline-flex')
  })
})
