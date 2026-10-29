/**
 * Attack surface > Certificates: the table shows issued-to, issuer, dates and
 * the status of each certificate, the fingerprint copies, the status filter
 * reaches the API, and nothing is fetched without assets:read.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ read: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    usePermissions: () => ({ can: () => perms.read }),
    useHasPermission: () => perms.read,
  }
})
const clip = vi.hoisted(() => ({ copyToClipboard: vi.fn().mockResolvedValue(true) }))
vi.mock('@/lib/clipboard', () => clip)

const { EASMCertificates } = await import('../easm-certificates')
const { certificatesCsv } = await import('../../lib/certificates')

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const FP = 'aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233'
const row = (over: Record<string, unknown>) => ({
  asset_id: '0198f0e2-0000-7000-8000-0000000000a1',
  name: 'cert-a',
  subject_cn: 'www.example.com',
  issuer_cn: 'Example CA',
  issuer_org: 'Example Trust',
  fingerprint_sha256: FP,
  not_before: '2025-01-01T00:00:00Z',
  not_after: '2026-01-01T00:00:00Z',
  status: 'expired',
  days_to_expiry: -10,
  is_self_signed: false,
  is_wildcard: false,
  first_seen: '2026-10-01T00:00:00Z',
  last_seen: '2026-10-20T00:00:00Z',
  ...over,
})

beforeEach(() => {
  api.get.mockReset().mockImplementation((url: string) =>
    Promise.resolve(
      url.includes('/stats')
        ? { total: 3, expired: 1, expiring_soon: 1, ok: 1, unknown: 0 }
        : {
            data: [
              row({}),
              row({
                asset_id: '0198f0e2-0000-7000-8000-0000000000a2',
                subject_cn: 'soon.example.com',
                status: 'expiring_soon',
                days_to_expiry: 5,
              }),
              row({
                asset_id: '0198f0e2-0000-7000-8000-0000000000a3',
                subject_cn: 'fine.example.com',
                status: 'ok',
                days_to_expiry: 200,
              }),
            ],
            total: 3,
          }
    )
  )
  clip.copyToClipboard.mockClear()
  perms.read = true
  window.history.replaceState(null, '', '/attack-surface/certificates')
})

describe('EASMCertificates', () => {
  it('lists certificates with issuer, dates and a status per row', async () => {
    wrap(<EASMCertificates />)
    expect(await screen.findByText('www.example.com')).toBeInTheDocument()
    expect(screen.getAllByText('Example CA').length).toBe(3)
    expect(screen.getAllByText('Example Trust').length).toBe(3)
    const states = Array.from(document.querySelectorAll('[data-state]')).map((e) =>
      e.getAttribute('data-state')
    )
    expect(states).toEqual(expect.arrayContaining(['expired', 'expiring_soon', 'ok']))
    expect(screen.getByText('in 5 days')).toBeInTheDocument()
    expect(screen.getByText('10 days ago')).toBeInTheDocument()
    // The summary strip counts come from the stats endpoint.
    expect(await screen.findByText('Expiring in 30 days')).toBeInTheDocument()
  })

  it('copies the full fingerprint', async () => {
    wrap(<EASMCertificates />)
    await screen.findByText('www.example.com')
    await userEvent.click(screen.getAllByRole('button', { name: 'Copy fingerprint' })[0])
    expect(clip.copyToClipboard).toHaveBeenCalledWith(FP)
  })

  it('sends the status filter to the API', async () => {
    window.history.replaceState(null, '', '/attack-surface/certificates?status=expired')
    wrap(<EASMCertificates />)
    await screen.findByText('www.example.com')
    await waitFor(() =>
      expect(api.get.mock.calls.some(([u]) => String(u).includes('status=expired'))).toBe(true)
    )
    expect(screen.getByText('Status is Expired')).toBeInTheDocument()
  })

  it('fetches nothing without assets:read', async () => {
    perms.read = false
    wrap(<EASMCertificates />)
    expect(await screen.findByText('Access denied')).toBeInTheDocument()
    expect(api.get).not.toHaveBeenCalled()
  })
})

describe('certificatesCsv', () => {
  it('neutralizes formulas in scan-controlled cells', () => {
    const csv = certificatesCsv(
      [row({ subject_cn: '=HYPERLINK("http://x")', issuer_org: '+cmd' }) as never],
      ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'],
      (s) => s
    )
    const lines = csv.split('\n')
    expect(lines[1]).toContain(`'=HYPERLINK`)
    expect(lines[1]).toContain(`'+cmd`)
    expect(lines[1]).toContain(FP)
  })
})
