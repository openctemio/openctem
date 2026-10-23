/**
 * Finding page load errors: a 404/403 shows the not-found copy (no oracle)
 * with no error toast and exactly one request; a 5xx or network failure shows
 * "could not load" with a Retry that fetches again.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import { ApiClientError } from '@/lib/api/error-handler'

const getMock = vi.fn()
const toastError = vi.fn()

vi.mock('next/navigation', () => ({
  useParams: () => ({ id: 'f-1' }),
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  usePathname: () => '/findings/f-1',
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('sonner', () => ({ toast: { error: (...a: unknown[]) => toastError(...a) } }))
vi.mock('@/lib/api/client', async (orig) => ({
  ...(await orig<typeof import('@/lib/api/client')>()),
  get: (...a: unknown[]) => getMock(...a),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't-1' } }),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
  useBreadcrumbTitle: () => {},
}))
vi.mock('@/features/findings/hooks/use-finding-activity-feed', () => ({
  useFindingActivityFeed: vi.fn(() => ({})),
}))
vi.mock('@/features/findings/hooks/use-finding-evidence-count', () => ({
  useFindingEvidenceCount: () => 0,
}))
vi.mock('@/features/findings/hooks/use-finding-triage', () => ({
  useFindingTriage: () => ({}),
}))
vi.mock('@/features/findings/components/detail', () => ({}))
vi.mock('@/features/findings/components/finding-activity', () => ({}))
vi.mock('@/features/findings/components/detail/pentest-details-tab', () => ({}))
vi.mock('@/features/remediation-hub/components/from-task-crumb', () => ({}))
vi.mock('@/features/remediation-hub/components/finding-task-band', () => ({}))
vi.mock('@/features/findings/config/register-layouts', () => ({}))

import FindingDetailPage from '../page'
import { useFindingActivityFeed } from '@/features/findings/hooks/use-finding-activity-feed'

function renderPage() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, errorRetryInterval: 10 }}>
      <FindingDetailPage />
    </SWRConfig>
  )
}

describe('finding page load errors', () => {
  beforeEach(() => {
    getMock.mockReset()
    toastError.mockReset()
    vi.mocked(useFindingActivityFeed).mockClear()
  })

  it('404 shows the not-found copy, one request, no toast, feed not enabled', async () => {
    getMock.mockRejectedValue(new ApiClientError('not found', 'NOT_FOUND', 404))
    renderPage()
    expect(await screen.findByText('Finding not found')).toBeInTheDocument()
    await new Promise((r) => setTimeout(r, 100))
    expect(getMock).toHaveBeenCalledTimes(1)
    expect(toastError).not.toHaveBeenCalled()
    expect(screen.queryByText('Retry')).not.toBeInTheDocument()
    for (const call of vi.mocked(useFindingActivityFeed).mock.calls) {
      expect(call[1]).toMatchObject({ enabled: false })
    }
  })

  it('403 shows the same copy as 404', async () => {
    getMock.mockRejectedValue(new ApiClientError('forbidden', 'FORBIDDEN', 403))
    renderPage()
    expect(await screen.findByText('Finding not found')).toBeInTheDocument()
    expect(toastError).not.toHaveBeenCalled()
  })

  it('500 shows could-not-load with Retry that fetches again', async () => {
    getMock.mockRejectedValue(new ApiClientError('boom', 'INTERNAL', 500))
    renderPage()
    const retry = await screen.findByRole('button', { name: 'Retry' })
    expect(screen.queryByText('Finding not found')).not.toBeInTheDocument()
    expect(toastError).not.toHaveBeenCalled()
    const before = getMock.mock.calls.length
    await userEvent.click(retry)
    await waitFor(() => expect(getMock.mock.calls.length).toBeGreaterThan(before))
  })
})
