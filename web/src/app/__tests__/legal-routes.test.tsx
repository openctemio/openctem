import { beforeEach, describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import { GET } from '../.well-known/security.txt/route'
import { LegalPage } from '@/features/legal/legal-page'
import { LEGAL_DOCS } from '@/lib/legal'
import { PUBLIC_ROUTES } from '@/lib/middleware/config'

vi.mock('next/navigation', () => ({
  notFound: () => {
    throw new Error('NEXT_NOT_FOUND')
  },
}))

// The legal information comes from the admin console through the API; the
// tests hand the record legalSettings() would return.
const settings = vi.hoisted(() => ({ current: {} as Record<string, string | undefined> }))
vi.mock('@/lib/legal-settings', () => ({ legalSettings: async () => settings.current }))

beforeEach(() => {
  settings.current = {}
})

describe('/.well-known/security.txt', () => {
  it('serves security@openctem.io by default as text/plain', async () => {
    const res = await GET()
    expect(res.status).toBe(200)
    expect(res.headers.get('Content-Type')).toBe('text/plain; charset=utf-8')
    expect(await res.text()).toMatch(/^Contact: mailto:security@openctem.io\nExpires: /)
  })

  it('names the contact set in the admin console', async () => {
    settings.current = { SECURITY_CONTACT: 'sec@example.com' }
    expect(await (await GET()).text()).toMatch(/^Contact: mailto:sec@example.com/)
  })

  it('answers 404 when turned off', async () => {
    settings.current = { SECURITY_TXT_ENABLED: 'false' }
    expect((await GET()).status).toBe(404)
  })
})

describe('legal pages', () => {
  it('are 404 unless the admin console turned them on', async () => {
    for (const d of LEGAL_DOCS) {
      await expect(LegalPage({ doc: d.doc })).rejects.toThrow('NEXT_NOT_FOUND')
    }
  })

  it.each(LEGAL_DOCS.map((d) => [d.title, d.doc] as const))(
    '%s renders with the OpenCTEM contacts and pending markers',
    async (title, doc) => {
      settings.current = { LEGAL_PAGES_ENABLED: 'true' }
      render(await LegalPage({ doc }))
      expect(screen.getByRole('heading', { level: 1, name: title })).toBeInTheDocument()
      expect(screen.getAllByText(/info@openctem\.io/).length).toBeGreaterThan(0)
      expect(screen.getAllByText(/to be confirmed/).length).toBeGreaterThan(0)
      expect(screen.getByRole('navigation', { name: 'Legal documents' })).toBeInTheDocument()
    }
  )

  it('the terms use the configured legal name once it is known', async () => {
    settings.current = { LEGAL_PAGES_ENABLED: 'true', LEGAL_ORGANIZATION_NAME: 'Acme Ltd' }
    render(await LegalPage({ doc: 'terms' }))
    expect(screen.getAllByText(/Acme Ltd/).length).toBeGreaterThan(0)
  })

  it('all open without a session', () => {
    for (const d of LEGAL_DOCS) {
      expect(PUBLIC_ROUTES).toContain(d.path)
    }
  })
})
