import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import ThreatIntelFeedsPage from '../../../app/(console)/system/threat-intel/page'
import type { ThreatIntelFeed } from '../types'

const mocks = vi.hoisted(() => ({
  sync: vi.fn(),
  success: vi.fn(),
  error: vi.fn(),
}))

vi.mock('sonner', () => ({ toast: { success: mocks.success, error: mocks.error } }))
vi.mock('../components/admin-console-shell', () => ({
  useAdmin: () => ({ role: 'super_admin' }),
}))
vi.mock('../api/use-system', async (orig) => ({
  ...(await orig<typeof import('../api/use-system')>()),
  useThreatIntelFeeds: () => ({
    data: [
      {
        source: 'vulnfeed',
        enabled: true,
        state: 'waiting_for_publisher',
        error_code: 'publisher_empty',
        last_error: 'vulnfeed fetch keyset.dsse.json: status 404',
        catalog_records: 0,
        records_changed: 0,
        interval_seconds: 1200,
        stale_after_seconds: 259200,
        detail: { applied_sequence: 0, keyset_version: 0, sources: [] },
      },
    ] satisfies ThreatIntelFeed[],
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
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

describe('Threat intelligence page: sync outcome', () => {
  beforeEach(() => vi.clearAllMocks())

  it('a failed feed is reported as failed, never as "Sync finished."', async () => {
    mocks.sync.mockResolvedValue({
      results: [
        { source: 'vulnfeed', records_synced: 0, duration_ms: 3, success: false, error: 'boom' },
      ],
    })
    render(<ThreatIntelFeedsPage />)
    await userEvent.click(screen.getByRole('button', { name: /sync all now/i }))
    await waitFor(() => expect(mocks.error).toHaveBeenCalled())
    expect(mocks.error.mock.calls[0][0]).toMatch(/Vulnerability bundles did not sync: boom/)
    expect(mocks.success).not.toHaveBeenCalled()
  })

  it('a successful sync says so, and the vulnfeed card has its own name', async () => {
    mocks.sync.mockResolvedValue({
      results: [{ source: 'vulnfeed', records_synced: 5, duration_ms: 3, success: true }],
    })
    render(<ThreatIntelFeedsPage />)
    expect(screen.getByText('Vulnerability bundles')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /^sync now$/i }))
    await waitFor(() => expect(mocks.success).toHaveBeenCalledWith('Sync finished.'))
    expect(mocks.error).not.toHaveBeenCalled()
  })
})

describe('Threat intelligence page: feed status', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows the state, the error as a code with an action, and the raw text only behind Details', async () => {
    render(<ThreatIntelFeedsPage />)
    expect(screen.getByText('Waiting for the publisher')).toBeInTheDocument()
    expect(screen.getByText('No bundle has been published yet.')).toBeInTheDocument()
    expect(screen.getByText(/Nothing to fix here/)).toBeInTheDocument()
    expect(screen.queryByText(/status 404/)).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /details/i }))
    expect(await screen.findByText(/status 404/)).toBeInTheDocument()
  })
})
