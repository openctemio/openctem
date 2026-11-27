import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { findingDetailHref } from '../finding-link'
import { FindingTitleCell } from '../../components/cells/finding-title-cell'

const HOSTILE = [
  '../../admin',
  'x/../../settings',
  '/../api/v1/tenants',
  'id?tenant=other',
  'id#frag',
  'javascript:alert(1)',
  '//evil.example/x',
  'https://evil.example',
  '%2e%2e%2fadmin',
  'a\\b',
  'a b\n',
]

/** The URL a browser resolves the href to, from a finding page. */
function resolved(href: string): URL {
  return new URL(href, 'https://app.example/findings?state=open')
}

describe('findingDetailHref', () => {
  it('a plain id is its page', () => {
    expect(findingDetailHref('01a1de93-2682-741a-92ce-14f8c2ba90d1')).toBe(
      '/findings/01a1de93-2682-741a-92ce-14f8c2ba90d1'
    )
  })

  it.each(HOSTILE)('a hostile id %j stays one segment under /findings/', (id) => {
    const href = findingDetailHref(id)
    expect(href.startsWith('/findings/')).toBe(true)
    const url = resolved(href)
    expect(url.origin).toBe('https://app.example')
    expect(url.search).toBe('')
    expect(url.hash).toBe('')
    // One path segment after /findings/: no slash survives, no dot segment resolves upward.
    expect(url.pathname).toMatch(/^\/findings\/[^/]+$/)
    expect(decodeURIComponent(url.pathname.slice('/findings/'.length))).toBe(id)
  })
})

describe('FindingTitleCell link', () => {
  it.each(HOSTILE)('renders the hostile id %j as a link inside /findings/', (id) => {
    render(
      <FindingTitleCell title="t" onOpen={vi.fn()} openLabel="t, view details" findingId={id} />
    )
    const link = screen.getByRole('link', { name: 't, view details' })
    const url = resolved(link.getAttribute('href') ?? '')
    expect(url.origin).toBe('https://app.example')
    expect(url.pathname).toMatch(/^\/findings\/[^/]+$/)
    expect(url.search + url.hash).toBe('')
  })
})
