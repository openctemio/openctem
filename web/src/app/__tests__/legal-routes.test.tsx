import { afterEach, describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import { GET } from '../.well-known/security.txt/route'
import AcceptableUsePage from '../acceptable-use/page'
import DataProcessingAddendumPage from '../dpa/page'
import PrivacyPage from '../privacy/page'
import SubprocessorsPage from '../subprocessors/page'
import TermsPage from '../terms/page'
import { LEGAL_DOCS } from '@/lib/legal'
import { PUBLIC_ROUTES } from '@/lib/middleware/config'

vi.mock('next/navigation', () => ({
  notFound: () => {
    throw new Error('NEXT_NOT_FOUND')
  },
}))

afterEach(() => vi.unstubAllEnvs())

const PAGES = [
  ['Terms of Service', TermsPage],
  ['Acceptable Use Policy', AcceptableUsePage],
  ['Privacy Policy', PrivacyPage],
  ['Data Processing Addendum', DataProcessingAddendumPage],
  ['Subprocessors', SubprocessorsPage],
] as const

describe('/.well-known/security.txt', () => {
  it('serves security@openctem.io by default as text/plain', async () => {
    vi.stubEnv('SECURITY_CONTACT', '')
    const res = GET()
    expect(res.status).toBe(200)
    expect(res.headers.get('Content-Type')).toBe('text/plain; charset=utf-8')
    expect(await res.text()).toMatch(/^Contact: mailto:security@openctem.io\nExpires: /)
  })

  it('answers 404 when turned off', () => {
    vi.stubEnv('SECURITY_TXT_ENABLED', 'false')
    expect(GET().status).toBe(404)
  })
})

describe('legal pages', () => {
  it('are 404 unless LEGAL_PAGES_ENABLED=true', () => {
    vi.stubEnv('LEGAL_PAGES_ENABLED', '')
    for (const [, Page] of PAGES) {
      expect(() => render(<Page />)).toThrow('NEXT_NOT_FOUND')
    }
  })

  it.each(PAGES)('%s renders with the OpenCTEM contacts and pending markers', (title, Page) => {
    vi.stubEnv('LEGAL_PAGES_ENABLED', 'true')
    vi.stubEnv('LEGAL_ORGANIZATION_NAME', '')
    render(<Page />)
    expect(screen.getByRole('heading', { level: 1, name: title })).toBeInTheDocument()
    expect(screen.getAllByText(/info@openctem\.io/).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/to be confirmed/).length).toBeGreaterThan(0)
    expect(screen.getByRole('navigation', { name: 'Legal documents' })).toBeInTheDocument()
  })

  it('the terms use the configured legal name once it is known', () => {
    vi.stubEnv('LEGAL_PAGES_ENABLED', 'true')
    vi.stubEnv('LEGAL_ORGANIZATION_NAME', 'Acme Ltd')
    render(<TermsPage />)
    expect(screen.getAllByText(/Acme Ltd/).length).toBeGreaterThan(0)
  })

  it('all open without a session', () => {
    for (const d of LEGAL_DOCS) {
      expect(PUBLIC_ROUTES).toContain(d.path)
    }
  })
})
