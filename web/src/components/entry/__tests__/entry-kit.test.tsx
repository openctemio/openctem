import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'

import {
  EntryActions,
  EntryBanner,
  EntryCard,
  EntryDivider,
  EntryFrame,
  EntryHeader,
  EntryLine,
} from '@/components/entry'

describe('EntryFrame', () => {
  it('has the brand link, one main region with the page, and the footer', () => {
    render(
      <EntryFrame termsUrl="/terms" privacyUrl="https://example.com/privacy">
        <EntryCard>
          <EntryHeader title="Sign in" />
        </EntryCard>
      </EntryFrame>
    )
    expect(screen.getByRole('link', { name: 'Go to sign in' })).toHaveAttribute('href', '/login')
    const main = screen.getByRole('main')
    expect(within(main).getByRole('heading', { level: 1, name: 'Sign in' })).toBeInTheDocument()

    const footer = screen.getByRole('contentinfo')
    expect(within(footer).getByRole('link', { name: 'Terms of Service' })).toHaveAttribute(
      'href',
      '/terms'
    )
    // A document hosted elsewhere opens in a new tab without an opener.
    const privacy = within(footer).getByRole('link', { name: /Privacy Policy/ })
    expect(privacy).toHaveAttribute('href', 'https://example.com/privacy')
    expect(privacy).toHaveAttribute('target', '_blank')
    expect(privacy.getAttribute('rel')).toContain('noopener')
    // One footer line, one text size: Language is drawn as one more footer
    // link (it inherits the footer's size), not a kit button of its own size.
    const language = within(footer).getByRole('button', { name: 'Language' })
    expect(language).not.toHaveAttribute('data-slot', 'button')
    expect(language.className).not.toMatch(/(^| )text-(xs|sm|base|dense|body|cap)( |$)/)
  })

  it('shows no legal link that is not configured', () => {
    render(
      <EntryFrame>
        <p>page</p>
      </EntryFrame>
    )
    const footer = screen.getByRole('contentinfo')
    expect(within(footer).queryByRole('link', { name: 'Terms of Service' })).toBeNull()
    expect(within(footer).queryByRole('link', { name: /Privacy Policy/ })).toBeNull()
  })

  it('sets the entry control scale (36px controls) on the whole page', () => {
    const { container } = render(
      <EntryFrame>
        <p>page</p>
      </EntryFrame>
    )
    expect(container.querySelector('[data-control-scale="entry"]')).not.toBeNull()
  })
})

describe('entry card parts', () => {
  it('announces a failure at once and a notice politely', () => {
    render(
      <>
        <EntryBanner tone="danger">Invalid email or password</EntryBanner>
        <EntryBanner tone="warn">Complete the security check</EntryBanner>
        <EntryBanner tone="info">Your session expired</EntryBanner>
        <EntryBanner tone="ok" title="Sent">
          Check your inbox
        </EntryBanner>
      </>
    )
    const alerts = screen.getAllByRole('alert')
    expect(alerts.map((a) => a.textContent)).toEqual([
      'Invalid email or password',
      'Complete the security check',
    ])
    const statuses = screen.getAllByRole('status')
    expect(statuses.map((s) => s.textContent)).toEqual([
      'Your session expired',
      'SentCheck your inbox',
    ])
  })

  it('lets a page choose the role of a banner', () => {
    render(
      <EntryBanner tone="info" role="alert">
        Use your organization&apos;s sign-in
      </EntryBanner>
    )
    expect(screen.getByRole('alert')).toHaveAttribute('data-tone', 'info')
  })

  it('titles a page with an h1 and a step or second card with an h2', () => {
    render(
      <>
        <EntryHeader title="Sign in" description="Enter your email" />
        <EntryHeader level={2} title="Link Google to your account?" />
      </>
    )
    expect(screen.getByRole('heading', { level: 1, name: 'Sign in' })).toBeInTheDocument()
    expect(
      screen.getByRole('heading', { level: 2, name: 'Link Google to your account?' })
    ).toBeInTheDocument()
    expect(screen.getByText('Enter your email')).toBeInTheDocument()
  })

  it('renders the divider label, lines and actions as given', () => {
    render(
      <EntryCard aria-label="card">
        <EntryDivider>Or continue with</EntryDivider>
        <EntryActions>
          <button type="button">Continue</button>
        </EntryActions>
        <EntryLine>Have an account?</EntryLine>
      </EntryCard>
    )
    const card = screen.getByRole('region', { name: 'card' })
    expect(within(card).getByText('Or continue with')).toBeInTheDocument()
    expect(within(card).getByRole('button', { name: 'Continue' })).toBeInTheDocument()
    expect(within(card).getByText('Have an account?')).toBeInTheDocument()
  })
})
