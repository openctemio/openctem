import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const elevate = vi.fn()
const end = vi.fn()
vi.mock('../api/use-admin-session', () => ({
  adminElevate: (...a: unknown[]) => elevate(...a),
  adminEndElevation: (...a: unknown[]) => end(...a),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver
Element.prototype.scrollIntoView ??= function () {}
Element.prototype.hasPointerCapture ??= () => false

import { AdminElevationBar } from '../components/admin-elevation-bar'
import type { AdminIdentity } from '../types'

const base: AdminIdentity = { id: '1', email: 'root@x.io', name: 'Root', role: 'readonly' }

describe('AdminElevationBar', () => {
  beforeEach(() => vi.clearAllMocks())

  it('offers elevation to a read-only-acting administrator and sends role, minutes and reason', async () => {
    const changed = vi.fn()
    elevate.mockResolvedValueOnce({ role: 'super_admin', elevated_until: '2026-10-16T12:00:00Z' })
    const user = userEvent.setup()
    render(<AdminElevationBar admin={{ ...base, max_role: 'super_admin' }} onChanged={changed} />)
    await user.click(screen.getByRole('button', { name: 'Elevate' }))
    await user.type(screen.getByLabelText('Reason'), 'Rotate the platform IdP secret, ticket 77')
    await user.click(screen.getAllByRole('button', { name: 'Elevate' }).at(-1)!)
    expect(elevate).toHaveBeenCalledWith(
      'super_admin',
      30,
      'Rotate the platform IdP secret, ticket 77'
    )
    expect(changed).toHaveBeenCalled()
  })

  it('shows the active elevation and ends it', async () => {
    const changed = vi.fn()
    end.mockResolvedValueOnce(undefined)
    const user = userEvent.setup()
    render(
      <AdminElevationBar
        admin={{
          ...base,
          role: 'ops_admin',
          max_role: 'super_admin',
          elevated_until: new Date(Date.now() + 600000).toISOString(),
        }}
        onChanged={changed}
      />
    )
    expect(screen.getByText(/Acting as Operations admin until/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'End now' }))
    expect(end).toHaveBeenCalled()
  })

  it('stays out of the way for a read-only administrator, and when elevation is not required', () => {
    const { container, rerender } = render(
      <AdminElevationBar admin={{ ...base, max_role: 'readonly' }} onChanged={vi.fn()} />
    )
    expect(container).toBeEmptyDOMElement()
    rerender(
      <AdminElevationBar
        admin={{ ...base, role: 'super_admin', max_role: 'super_admin' }}
        onChanged={vi.fn()}
      />
    )
    expect(container).toBeEmptyDOMElement()
  })
})
