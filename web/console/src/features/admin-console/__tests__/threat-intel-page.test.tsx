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
        last_sync_status: 'failed',
        records_synced: 0,
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
