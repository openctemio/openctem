/**
 * Attack surface > Technologies: one row per technology and version with its
 * asset count (a link to the inventory filtered to that exact version), CVE
 * figures and exploit state; the toggles and sort reach the API; the CSV is
 * formula safe; nothing is fetched without assets:read.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ read: true, vulns: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    usePermissions: () => ({ can: () => perms.read }),
    useHasPermission: (p: string) =>
      p === actual.Permission.VulnerabilitiesRead ? perms.vulns : perms.read,
  }
})

const { EASMTechnologies } = await import('../easm-technologies')
const { technologiesCsv, technologyAssetsHref, technologiesUrl } =
  await import('../../lib/technologies')

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const row = (over: Record<string, unknown>) => ({
  key: 'nginx',
  name: 'nginx',
  version: '1.18.0',
  version_known: true,
  category: 'web_server',
  vendor: 'F5',
  sources: ['httpx'],
  asset_count: 4,
  cve_count: 3,
  top_cve: 'CVE-2021-23017',
  top_cvss: 9.8,
  kev: true,
  exploit_available: true,
  active_alerts: 1,
  first_seen: '2026-10-01T00:00:00Z',
  last_seen: '2026-10-20T00:00:00Z',
  ...over,
})

beforeEach(() => {
  api.get.mockReset().mockImplementation((url: string) =>
    Promise.resolve(
      url.includes('/stats')
        ? { total: 2, with_cves: 1, kev: 1, unknown_version: 1, with_alerts: 1 }
        : {
            data: [
              row({}),
              row({
                key: 'react',
                name: 'React',
                version: '',
                version_known: false,
                category: 'js_library',
                vendor: undefined,
                asset_count: 2,
                cve_count: 0,
                top_cve: undefined,
                top_cvss: undefined,
                kev: false,
                exploit_available: false,
                active_alerts: 0,
              }),
            ],
            total: 2,
          }
    )
  )
  perms.read = true
  perms.vulns = true
  window.history.replaceState(null, '', '/attack-surface/technologies')
})

describe('EASMTechnologies', () => {
  it('lists version rows with assets, CVEs, exploit state and alerts', async () => {
    wrap(<EASMTechnologies />)
    expect(await screen.findByText('nginx')).toBeInTheDocument()
    expect(screen.getByText('1.18.0')).toBeInTheDocument()
    expect(screen.getByText('F5')).toBeInTheDocument()
    expect(screen.getByText('3 CVEs')).toBeInTheDocument()
    expect(screen.getByText('None known')).toBeInTheDocument()
    // The unknown version reads as such, never as an empty cell.
    expect(screen.getAllByText('Unknown').length).toBeGreaterThan(0)
    const top = screen.getByRole('link', { name: 'CVE-2021-23017 (CVSS 9.8)' })
    expect(top).toHaveAttribute('href', '/vulnerabilities/CVE-2021-23017')
    const assets = screen.getByRole('link', { name: 'Open the 4 assets running nginx' })
    expect(assets).toHaveAttribute('href', '/assets?technology=nginx&technology_version=1.18.0')
    expect(await screen.findByText('Known exploited')).toBeInTheDocument()
  })

  it('shows the top CVE as text without vulnerabilities:read', async () => {
    perms.vulns = false
    wrap(<EASMTechnologies />)
    expect(await screen.findByText('CVE-2021-23017 (CVSS 9.8)')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'CVE-2021-23017 (CVSS 9.8)' })).toBeNull()
  })

  it('sends the strip toggles and the default sort to the API', async () => {
    wrap(<EASMTechnologies />)
    await screen.findByText('nginx')
    expect(api.get.mock.calls.some(([u]) => String(u).includes('sort=-asset_count'))).toBe(true)
    await userEvent.click(screen.getByRole('button', { name: /With known CVEs/ }))
    await waitFor(() =>
      expect(api.get.mock.calls.some(([u]) => String(u).includes('has_cves=true'))).toBe(true)
    )
  })

  it('reads the version filter from the URL', async () => {
    window.history.replaceState(null, '', '/attack-surface/technologies?version=unknown')
    wrap(<EASMTechnologies />)
    await screen.findByText('nginx')
    await waitFor(() =>
      expect(api.get.mock.calls.some(([u]) => String(u).includes('version_known=false'))).toBe(true)
    )
  })

  it('fetches nothing without assets:read', async () => {
    perms.read = false
    wrap(<EASMTechnologies />)
    expect(await screen.findByText('Access denied')).toBeInTheDocument()
    expect(api.get).not.toHaveBeenCalled()
  })
})

describe('technologies lib', () => {
  it('drills an unknown version down with an empty technology_version', () => {
    expect(technologyAssetsHref({ key: 'react', version: '' })).toBe(
      '/assets?technology=react&technology_version='
    )
  })

  it('builds the list URL from the filters', () => {
    expect(
      technologiesUrl(
        { q: ' ng ', category: 'web_server', version: 'known', withCves: true, kev: true },
        { page: 2, perPage: 50 },
        '-cve_count'
      )
    ).toBe(
      '/api/v1/attack-surface/technologies?q=ng&category=web_server&version_known=true&has_cves=true&kev=true&sort=-cve_count&page=2&per_page=50'
    )
  })

  it('neutralizes formulas in scan-controlled cells', () => {
    const csv = technologiesCsv(
      [row({ name: '=HYPERLINK("http://x")', vendor: '+cmd' }) as never],
      ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j']
    )
    const line = csv.split('\n')[1]
    expect(line).toContain(`'=HYPERLINK`)
    expect(line).toContain(`'+cmd`)
    expect(line).toContain('KEV')
  })
})
