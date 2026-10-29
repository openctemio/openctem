import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import ThreatIntelFeedsPage from '../../../app/(console)/system/threat-intel/page'
import type { ThreatIntelFeed } from '../types'

const mocks = vi.hoisted(() => ({
  sync: vi.fn(),
  success: vi.fn(),
  error: vi.fn(),
  feeds: { current: [] as ThreatIntelFeed[] },
  mutate: vi.fn(),
  fast: vi.fn(),
}))

vi.mock('sonner', () => ({ toast: { success: mocks.success, error: mocks.error } }))
vi.mock('../components/admin-console-shell', () => ({
  useAdmin: () => ({ role: 'super_admin' }),
}))
vi.mock('../api/use-system', async (orig) => ({
  ...(await orig<typeof import('../api/use-system')>()),
  useThreatIntelFeeds: (fast?: boolean) => {
    mocks.fast(fast)
    return { data: mocks.feeds.current, error: undefined, isLoading: false, mutate: mocks.mutate }
  },
  syncThreatIntel: mocks.sync,
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

function feed(patch: Partial<ThreatIntelFeed>): ThreatIntelFeed {
  return {
    source: 'vulnfeed',
    enabled: true,
    state: 'up_to_date',
    catalog_records: 0,
    records_changed: 0,
    interval_seconds: 1200,
    stale_after_seconds: 259200,
    last_attempt_at: '2026-10-26T10:00:00Z',
    detail: { applied_sequence: 0, keyset_version: 0, sources: [] },
    ...patch,
  }
}

describe('Threat intelligence page: queued sync', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.feeds.current = [feed({})]
  })

  it('says the sync started, then reports the real outcome when the feed settles', async () => {
    mocks.sync.mockResolvedValue({ results: [{ source: 'vulnfeed', status: 'queued' }] })
    const { rerender } = render(<ThreatIntelFeedsPage />)
    await userEvent.click(screen.getByRole('button', { name: /sync all now/i }))
    await waitFor(() =>
      expect(mocks.success).toHaveBeenCalledWith(expect.stringMatching(/started/i))
    )
    expect(mocks.error).not.toHaveBeenCalled()
    await waitFor(() => expect(mocks.fast).toHaveBeenLastCalledWith(true))

    // Running: no outcome yet.
    mocks.feeds.current = [feed({ state: 'running' })]
    rerender(<ThreatIntelFeedsPage />)
    expect(screen.getByRole('button', { name: 'Running' })).toBeDisabled()
    expect(mocks.error).not.toHaveBeenCalled()

    // Settled as a failure: the real outcome, never "synced".
    mocks.success.mockClear()
    mocks.feeds.current = [
      feed({
        state: 'failing',
        error_code: 'http_status',
        error_params: { host: 'github.com', status: '503' },
        last_attempt_at: '2026-10-26T10:05:00Z',
      }),
    ]
    rerender(<ThreatIntelFeedsPage />)
    await waitFor(() => expect(mocks.error).toHaveBeenCalled())
    expect(mocks.error.mock.calls[0][0]).toBe('Vulnerability bundles: github.com answered 503.')
    expect(mocks.success).not.toHaveBeenCalled()
  })

  it('reports a feed that finished well', async () => {
    mocks.sync.mockResolvedValue({ results: [{ source: 'vulnfeed', status: 'queued' }] })
    const { rerender } = render(<ThreatIntelFeedsPage />)
    await userEvent.click(screen.getByRole('button', { name: /^sync now$/i }))
    await waitFor(() => expect(mocks.sync).toHaveBeenCalledWith('vulnfeed'))
    mocks.feeds.current = [feed({ last_attempt_at: '2026-10-26T10:06:00Z' })]
    rerender(<ThreatIntelFeedsPage />)
    await waitFor(() => expect(mocks.success).toHaveBeenCalledWith('Vulnerability bundles synced.'))
  })

  it('a feed the server did not start is reported as not started', async () => {
    mocks.sync.mockResolvedValue({
      results: [{ source: 'vulnfeed', status: 'skipped', reason: 'not_configured' }],
    })
    render(<ThreatIntelFeedsPage />)
    await userEvent.click(screen.getByRole('button', { name: /sync all now/i }))
    await waitFor(() => expect(mocks.error).toHaveBeenCalled())
    expect(mocks.error.mock.calls[0][0]).toBe(
      'Vulnerability bundles was not started: bundle import is not configured.'
    )
    expect(mocks.success).not.toHaveBeenCalled()
  })
})

describe('Threat intelligence page: feed status', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows the state, the error as a code with an action, and the raw text only behind Details', async () => {
    mocks.feeds.current = [
      feed({
        state: 'waiting_for_publisher',
        error_code: 'publisher_empty',
        last_error: 'vulnfeed fetch keyset.dsse.json: status 404',
      }),
    ]
    render(<ThreatIntelFeedsPage />)
    expect(screen.getByText('Waiting for the publisher')).toBeInTheDocument()
    expect(screen.getByText('No bundle has been published yet.')).toBeInTheDocument()
    expect(screen.getByText(/Nothing to fix here/)).toBeInTheDocument()
    expect(screen.queryByText(/status 404/)).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /details/i }))
    expect(await screen.findByText(/status 404/)).toBeInTheDocument()
  })
})
