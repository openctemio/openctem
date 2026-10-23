import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'

import Page from '../page'

const getMock = vi.fn()
vi.mock('@/lib/api/client', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/api/client')>()),
  get: (...a: unknown[]) => getMock(...a),
}))
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  useHasPermission: () => true,
  Can: ({ children }: { children: React.ReactNode }) => children,
}))
vi.mock('@/features/shared/components/gated-section-tabs', () => ({ GatedSectionTabs: () => null }))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1' } }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const renderPage = () =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <Page />
    </SWRConfig>
  )

describe('business-services page load failure', () => {
  beforeEach(() => getMock.mockReset())

  it('shows the shared error state with retry, not the empty state', async () => {
    getMock.mockRejectedValue(new Error('boom'))
    renderPage()
    const retry = await screen.findByRole('button', { name: /retry/i })
    expect(screen.queryByText(/No business services yet|Create a service to get started/i)).toBeNull()
    const calls = getMock.mock.calls.length
    getMock.mockResolvedValue({ data: [], total: 0 })
    await userEvent.setup().click(retry)
    await waitFor(() => expect(getMock.mock.calls.length).toBeGreaterThan(calls))
  })
})
