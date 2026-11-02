/**
 * Attack surface > Discovery: four stage cards with status, progress and the
 * auto-validation count; Run and Run all reach the API; Abort all asks first;
 * a stage run within the minute and coverage switched off disable Run; the
 * CSV is formula safe; nothing is fetched without scans:read.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ read: true, run: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    usePermissions: () => ({
      can: (p: string) => (p === actual.Permission.ScansRead ? perms.read : perms.run),
    }),
  }
})
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }))

const { EASMDiscovery } = await import('../easm-discovery')
const { discoveryCsv } = await import('../../lib/discovery')
type Overview = import('../../lib/discovery').DiscoveryOverview

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const later = new Date(Date.now() + 45_000).toISOString()

function overview(over: Partial<Overview> = {}): Overview {
  return {
    generated_at: new Date().toISOString(),
    loop_enabled: true,
    coverage_enabled: true,
    pass_every_seconds: 60,
    daily_budget: 5000,
    budget_used: 120,
    auto_validation: { assets: 7 },
    stages: [
      {
        stage: 'asset_discovery',
        status: 'running',
        progress_done: 2,
        progress_total: 5,
        progress_unit: 'tasks',
        last_run_at: '2026-10-30T10:00:00Z',
        capabilities: [
          {
            capability: 'discover.subdomains',
            pairs: 3,
            covered: 1,
            due_now: 0,
            queued: 2,
            failed: 0,
            blocked: 0,
            paused: 0,
          },
        ],
      },
      {
        stage: 'exposure_scan',
        status: 'failed',
        progress_done: 4,
        progress_total: 10,
        progress_unit: 'pairs',
        run_available_at: later,
        capabilities: [
          {
            capability: 'scan.ports',
            pairs: 10,
            covered: 4,
            due_now: 0,
            queued: 0,
            failed: 6,
            blocked: 0,
            paused: 0,
            paused_reason: '=HYPERLINK("x")',
          },
        ],
      },
      {
        stage: 'validation_scoping',
        status: 'paused',
        reason: 'tool_missing',
        progress_done: 0,
        progress_total: 2,
        progress_unit: 'pairs',
        auto_validated_assets: 7,
        capabilities: [
          {
            capability: 'resolve.dns',
            pairs: 2,
            covered: 0,
            due_now: 0,
            queued: 0,
            failed: 0,
            blocked: 0,
            paused: 2,
            paused_reason: 'tool_missing',
          },
        ],
      },
      {
        stage: 'technology_discovery',
        status: 'idle',
        progress_done: 0,
        progress_total: 0,
        progress_unit: 'pairs',
        capabilities: [],
      },
    ],
    ...over,
  }
}

beforeEach(() => {
  perms.read = true
  perms.run = true
  api.get.mockReset().mockResolvedValue(overview())
  api.post.mockReset().mockResolvedValue({
    started: ['technology_discovery'],
    skipped: [],
    capabilities: [],
    pairs_made_due: 3,
    next_pass_within_seconds: 60,
  })
})

describe('EASMDiscovery', () => {
  it('shows the four stages with status, reason, progress and the auto-validation count', async () => {
    wrap(<EASMDiscovery />)
    const cards = await screen.findAllByTestId(/^discovery-stage-/)
    expect(cards.map((c) => c.getAttribute('data-status'))).toEqual([
      'running',
      'failed',
      'paused',
      'idle',
    ])
    expect(within(cards[0]).getByText('2 of 5 tasks')).toBeInTheDocument()
    expect(within(cards[2]).getByText('No sensor has the tool')).toBeInTheDocument()
    expect(screen.getByTestId('discovery-auto-validated')).toHaveTextContent('7 assets')
    expect(screen.getByTestId('discovery-freshness')).toHaveTextContent('Updated')
    expect(api.get).toHaveBeenCalledWith('/api/v1/attack-surface/discovery')
  })

  it('makes every summary tile a link to the list it summarizes', async () => {
    wrap(<EASMDiscovery />)
    await screen.findAllByTestId(/^discovery-stage-/)
    const hrefs = screen
      .getAllByRole('link')
      .map((a) => a.getAttribute('href'))
      .filter((h) => ['/scans', '/attack-surface/review', '/scope'].includes(h ?? ''))
    expect(hrefs.sort()).toEqual(['/attack-surface/review', '/scans', '/scope'])
  })

  it('runs one stage and every stage through the typed commands', async () => {
    const user = userEvent.setup()
    wrap(<EASMDiscovery />)
    await user.click(await screen.findByRole('button', { name: 'Run Technology discovery' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/attack-surface/discovery/stages/technology_discovery/run',
        {}
      )
    )
    await user.click(screen.getByRole('button', { name: 'Run all' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/attack-surface/discovery/run', {})
    )
  })

  it('keeps Run disabled for a stage run within the minute', async () => {
    wrap(<EASMDiscovery />)
    const card = await screen.findByTestId('discovery-stage-exposure_scan')
    expect(within(card).getByRole('button', { name: 'Run Exposure scan' })).toBeDisabled()
  })

  it('asks before aborting, then cancels', async () => {
    const user = userEvent.setup()
    api.post.mockResolvedValue({ canceled: 1, failed: 0 })
    wrap(<EASMDiscovery />)
    await screen.findAllByTestId(/^discovery-stage-/)
    await user.click(screen.getByRole('button', { name: 'Abort all' }))
    expect(api.post).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    await user.click(within(dialog).getByRole('button', { name: 'Abort all' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/attack-surface/discovery/cancel', {})
    )
  })

  it('explains and disables running while automatic coverage is off', async () => {
    api.get.mockResolvedValue(overview({ coverage_enabled: false }))
    wrap(<EASMDiscovery />)
    expect(
      await screen.findByText(/Automatic coverage is off for your organization/)
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Run all' })).toBeDisabled()
  })

  it('disables the actions without the scan permissions', async () => {
    perms.run = false
    wrap(<EASMDiscovery />)
    await screen.findAllByTestId(/^discovery-stage-/)
    expect(screen.getByRole('button', { name: 'Run all' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Abort all' })).toBeDisabled()
  })

  it('fetches nothing without scans:read', () => {
    perms.read = false
    wrap(<EASMDiscovery />)
    expect(api.get).not.toHaveBeenCalled()
    expect(screen.getByText('Access denied')).toBeInTheDocument()
  })

  it('builds a formula-safe CSV with one row per stage and capability', () => {
    const csv = discoveryCsv(overview())
    const lines = csv.split('\n')
    expect(lines).toHaveLength(4)
    expect(lines[0].startsWith('stage,stage_status')).toBe(true)
    expect(csv).not.toMatch(/,=HYPERLINK/)
  })
})
