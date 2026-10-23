import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'

import CyclesPage from '../page'

const getMock = vi.fn()
let granted = new Set<string>()
const postMock = vi.fn()
const toastError = vi.fn()

vi.mock('@/lib/api/client', () => ({
  get: (...a: unknown[]) => getMock(...a),
  post: (...a: unknown[]) => postMock(...a),
}))
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  useHasPermission: (p: string) => granted.has(p),
  Can: ({ children, permission }: { children: React.ReactNode; permission: string }) =>
    granted.has(permission) ? children : null,
}))
vi.mock('@/features/cycles', () => ({
  CyclePolicyCard: () => null,
  summarizeEvaluation: () => null,
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: (m: string) => toastError(m) } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

// A fresh SWR cache per render so one test's response never leaks into the next.
const renderPage = () =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <CyclesPage />
    </SWRConfig>
  )

describe('cycles page', () => {
  beforeEach(() => {
    getMock.mockReset()
    getMock.mockResolvedValue({ data: [], total: 0 })
    granted = new Set(['ctem:cycles:write'])
    postMock.mockReset()
    toastError.mockClear()
  })

  it('shows New cycle only with ctem:cycles:write', () => {
    const { unmount } = renderPage()
    expect(screen.getByRole('button', { name: /new cycle/i })).toBeInTheDocument()
    unmount()
    granted = new Set()
    renderPage()
    expect(screen.queryByRole('button', { name: /new cycle/i })).toBeNull()
  })

  it('shows an error with retry instead of "No cycles yet" when the list fails', async () => {
    getMock.mockRejectedValue(new Error('boom'))
    renderPage()
    const retry = await screen.findByRole('button', { name: /retry/i })
    expect(screen.queryByText('No cycles yet')).toBeNull()
    const calls = getMock.mock.calls.length
    await userEvent.setup().click(retry)
    await waitFor(() => expect(getMock.mock.calls.length).toBeGreaterThan(calls))
  })

  it('creates once on a double click and shows the API message on failure', async () => {
    let reject: (e: Error) => void = () => {}
    postMock.mockImplementation(() => new Promise((_, r) => (reject = r)))
    const user = userEvent.setup()
    renderPage()
    await user.click(screen.getByRole('button', { name: /new cycle/i }))
    await user.type(await screen.findByLabelText(/name/i), 'Q4')
    const create = screen.getByRole('button', { name: 'Create' })
    await user.click(create)
    await user.click(create)
    expect(postMock).toHaveBeenCalledTimes(1)
    expect(create).toBeDisabled()
    reject(new Error('cycle name taken'))
    await waitFor(() => expect(toastError).toHaveBeenCalledWith('cycle name taken'))
  })

  it('refuses an end date before the start date', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(screen.getByRole('button', { name: /new cycle/i }))
    await user.type(await screen.findByLabelText(/^name/i), 'Q4')
    await user.type(screen.getByLabelText('Start date'), '2026-10-10')
    await user.type(screen.getByLabelText('End date'), '2026-10-01')
    await user.click(screen.getByRole('button', { name: 'Create' }))
    expect(postMock).not.toHaveBeenCalled()
    expect(toastError).toHaveBeenCalledWith(expect.stringMatching(/end date/i))
  })
})
