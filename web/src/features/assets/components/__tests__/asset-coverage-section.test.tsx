/**
 * Asset coverage (RFC-093): one line per capability with its state, the
 * reason it was skipped and when it last ran; gaps flagged; nothing fetched
 * without assets:read.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'
import { AssetCoverageSection } from '../asset-coverage-section'
import type { AssetCoverage } from '../../lib/asset-coverage'

const api = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn(), del: vi.fn(), post: vi.fn() }))
vi.mock('@/lib/api/client', () => api)

let perms: string[] = []
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return { ...actual, usePermissions: () => ({ can: (p: string) => perms.includes(p) }) }
})

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const coverage: AssetCoverage = {
  asset_id: 'a1',
  gaps: 1,
  entries: [
    {
      capability: 'probe.http',
      state: 'covered',
      gap: false,
      last_success_at: new Date().toISOString(),
      last_outcome: 'no_output',
    },
    { capability: 'scan.ports', state: 'blocked', gap: false, reason: 'shared_network' },
    {
      capability: 'vuln.templates',
      state: 'failed',
      gap: true,
      last_error: 'sensor unreachable',
      fail_streak: 3,
    },
    { capability: 'resolve.dns', state: 'not_applicable', gap: false, reason: 'resolves' },
    { capability: 'discover.subdomains', state: 'paused', gap: false, reason: 'not_claimed' },
  ],
}

describe('AssetCoverageSection', () => {
  beforeEach(() => {
    api.get.mockReset()
    perms = ['assets:read']
  })

  it('explains each capability: state, reason, last run, gaps', async () => {
    api.get.mockResolvedValue(coverage)
    wrap(<AssetCoverageSection assetId="a1" />)
    expect(await screen.findByText('HTTP probe')).toBeInTheDocument()
    expect(api.get).toHaveBeenCalledWith('/api/v1/assets/a1/coverage')
    expect(screen.getByText('1 gaps')).toBeInTheDocument()
    expect(screen.getByText(/found nothing/)).toBeInTheDocument()
    expect(screen.getByText(/shared or CDN network/)).toBeInTheDocument()
    expect(screen.getByText('sensor unreachable')).toBeInTheDocument()
    expect(screen.getByText('Gap')).toBeInTheDocument()
    expect(screen.getByText('Blocked')).toBeInTheDocument()
    expect(screen.getByText(/the name does not resolve/)).toBeInTheDocument()
    expect(screen.getByText(/no sensor took its last runs/)).toBeInTheDocument()
  })

  it('says when nothing is scanned automatically', async () => {
    api.get.mockResolvedValue({ asset_id: 'a1', gaps: 0, entries: [] })
    wrap(<AssetCoverageSection assetId="a1" />)
    expect(
      await screen.findByText('Nothing is scanned automatically for this kind of asset.')
    ).toBeInTheDocument()
  })

  it('fetches nothing without assets:read', () => {
    perms = []
    wrap(<AssetCoverageSection assetId="a1" />)
    expect(api.get).not.toHaveBeenCalled()
  })
})
