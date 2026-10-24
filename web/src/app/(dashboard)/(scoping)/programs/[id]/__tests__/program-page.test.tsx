import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Suspense } from 'react'

import ProgramPage from '../page'

const mutate = vi.fn()
let state: { data?: unknown; error?: unknown } = {}

vi.mock('@/features/programs', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/features/programs')>()),
  useProgram: () => ({ ...state, mutate }),
  invalidatePrograms: vi.fn(),
}))
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  useHasPermission: () => true,
  usePermissions: () => ({ isOwner: false, can: () => true }),
}))

// One promise for every render: `use(params)` suspends on a new promise each time.
const params = Promise.resolve({ id: 'p1' })
const renderPage = async () => {
  let out!: ReturnType<typeof render>
  await act(async () => {
    out = render(
      <Suspense fallback={null}>
        <ProgramPage params={params} />
      </Suspense>
    )
  })
  return out
}

describe('program page', () => {
  beforeEach(() => mutate.mockClear())

  it('offers Retry and a way back when the read fails', async () => {
    state = { error: new Error('boom') }
    await renderPage()
    const retry = await screen.findByRole('button', { name: /retry/i })
    await userEvent.setup().click(retry)
    expect(mutate).toHaveBeenCalled()
    expect(screen.getByRole('link', { name: /back to programs/i })).toHaveAttribute(
      'href',
      '/programs'
    )
  })

  it('renders skeletons while loading, not a blank page', async () => {
    state = {}
    const { container } = await renderPage()
    await vi.waitFor(() =>
      expect(
        container.querySelectorAll('[data-slot="skeleton"], .animate-pulse').length
      ).toBeGreaterThan(0)
    )
  })
})
