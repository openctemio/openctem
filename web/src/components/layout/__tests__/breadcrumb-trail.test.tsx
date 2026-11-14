import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

const pathname = vi.hoisted(() => ({ current: '/x/y' }))
vi.mock('next/navigation', () => ({ usePathname: () => pathname.current }))

const { BreadcrumbNav } = await import('../breadcrumb-nav')

/**
 * A shell that names its own pages (the platform console) passes the levels;
 * the URL is not read for labels, and a level without a page is plain text.
 */
describe('BreadcrumbNav with a given trail', () => {
  it('renders the given levels with the given home name, the last one current', () => {
    pathname.current = '/system/email'
    render(
      <BreadcrumbNav
        trail={{
          homeLabel: 'Overview',
          levels: [
            { path: '/organizations', label: 'Organizations', hasPage: true },
            { path: '/organizations/abc', label: 'Organization', hasPage: true },
          ],
        }}
      />
    )
    expect(screen.getByText('Overview')).toHaveClass('sr-only')
    expect(screen.getByRole('link', { name: 'Overview' })).toHaveAttribute('href', '/')
    expect(screen.getByRole('link', { name: 'Organizations' })).toHaveAttribute(
      'href',
      '/organizations'
    )
    expect(screen.getByText('Organization')).toHaveAttribute('aria-current', 'page')
    // Nothing from the URL's own segments.
    expect(screen.queryByText(/system|email/i)).not.toBeInTheDocument()
  })

  it('renders an ancestor without a page as text, not a link', () => {
    render(
      <BreadcrumbNav
        trail={{
          homeLabel: 'Overview',
          levels: [
            { path: '/folder', label: 'Folder', hasPage: false },
            { path: '/folder/page', label: 'Page', hasPage: true },
          ],
        }}
      />
    )
    expect(screen.queryByRole('link', { name: 'Folder' })).not.toBeInTheDocument()
    expect(screen.getAllByText('Folder').length).toBeGreaterThan(0)
  })

  it('shows no trail for an empty list (the home page)', () => {
    const { container } = render(<BreadcrumbNav trail={{ homeLabel: 'Overview', levels: [] }} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('still builds the tenant trail from the URL without one', () => {
    pathname.current = '/findings'
    render(<BreadcrumbNav />)
    expect(screen.getByRole('link', { name: 'Dashboard' })).toHaveAttribute('href', '/')
    expect(screen.getByText('Findings')).toHaveAttribute('aria-current', 'page')
  })
})
