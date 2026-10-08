import { afterEach, describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import { GET } from '../.well-known/security.txt/route'
import PrivacyPage from '../privacy/page'
import TermsPage from '../terms/page'
import { PUBLIC_ROUTES } from '@/lib/middleware/config'

vi.mock('next/navigation', () => ({
  notFound: () => {
    throw new Error('NEXT_NOT_FOUND')
  },
}))

afterEach(() => vi.unstubAllEnvs())

describe('/.well-known/security.txt', () => {
  it('answers 404 without a contact', async () => {
    vi.stubEnv('SECURITY_CONTACT', '')
    const res = GET()
    expect(res.status).toBe(404)
  })

  it('serves the configured contact as text/plain', async () => {
    vi.stubEnv('SECURITY_CONTACT', 'security@example.com')
    const res = GET()
    expect(res.status).toBe(200)
    expect(res.headers.get('Content-Type')).toBe('text/plain; charset=utf-8')
    expect(await res.text()).toMatch(/^Contact: mailto:security@example.com\nExpires: /)
  })
})

describe('/terms and /privacy', () => {
  it('are 404 unless LEGAL_PAGES_ENABLED=true', () => {
    vi.stubEnv('LEGAL_PAGES_ENABLED', '')
    expect(() => TermsPage()).toThrow('NEXT_NOT_FOUND')
    expect(() => PrivacyPage()).toThrow('NEXT_NOT_FOUND')
  })

  it('render the templates filled from the environment, placeholders otherwise', () => {
    vi.stubEnv('LEGAL_PAGES_ENABLED', 'true')
    vi.stubEnv('LEGAL_ORGANIZATION_NAME', 'Acme Ltd')
    vi.stubEnv('LEGAL_CONTACT_EMAIL', '')
    render(TermsPage())
    expect(screen.getByRole('heading', { level: 1, name: 'Terms of Service' })).toBeInTheDocument()
    expect(screen.getAllByText(/Acme Ltd/).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/\[Contact email\]/).length).toBeGreaterThan(0)
  })

  it('open without a session', () => {
    expect(PUBLIC_ROUTES).toContain('/terms')
    expect(PUBLIC_ROUTES).toContain('/privacy')
  })
})
