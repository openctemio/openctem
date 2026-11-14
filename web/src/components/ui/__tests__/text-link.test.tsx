import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { TextLink } from '../text-link'

describe('TextLink', () => {
  it('a standalone link is plain at rest and underlined on hover and focus', () => {
    render(<TextLink href="/findings">Findings</TextLink>)
    const a = screen.getByRole('link', { name: 'Findings' })
    expect(a).toHaveAttribute('href', '/findings')
    expect(a.className).toMatch(/\bhover:underline\b/)
    expect(a.className).toMatch(/\bfocus-visible:underline\b/)
    expect(a.className).not.toMatch(/(^|\s)underline(\s|$)/)
  })

  it('an inline link is underlined at rest in the signal colour', () => {
    render(
      <TextLink href="/docs" variant="inline">
        the guide
      </TextLink>
    )
    const a = screen.getByRole('link', { name: 'the guide' })
    expect(a.className).toMatch(/(^|\s)underline(\s|$)/)
    expect(a.className).toContain('text-signal-text')
    expect(a.className).toContain('decoration-signal-text/45')
  })

  it('an external link opens a new tab safely and says so', () => {
    render(
      <TextLink href="https://example.com/a" external>
        Advisory
      </TextLink>
    )
    const a = screen.getByRole('link', { name: /Advisory/ })
    expect(a).toHaveAttribute('target', '_blank')
    expect(a.getAttribute('rel')).toContain('noopener')
    expect(a).toHaveTextContent('(opens in a new tab)')
  })

  it('refuses a script URL, internal or external, and keeps the text', () => {
    render(
      <>
        <TextLink href="javascript:alert(1)">Bad</TextLink>
        <TextLink href="javascript:alert(1)" external>
          Bad external
        </TextLink>
      </>
    )
    expect(screen.queryByRole('link')).toBeNull()
    expect(screen.getByText('Bad')).toHaveAttribute('data-unsafe-href')
    expect(screen.getByText(/Bad external/).closest('[data-unsafe-href]')).not.toBeNull()
  })
})
