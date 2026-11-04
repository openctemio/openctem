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
const factors = vi.fn()
vi.mock('../api/use-console-factors', () => ({
  useConsoleFactors: () => ({ data: factors() }),
}))
vi.mock('../lib/webauthn', () => ({ isWebAuthnSupported: () => true }))
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
  beforeEach(() => {
    vi.clearAllMocks()
    factors.mockReturnValue({ totp_allowed: true, webauthn_enabled: false, authenticators: [] })
  })

  it('elevates in one dialog: role, minutes, reason and the code go in one request', async () => {
    const changed = vi.fn()
    elevate.mockResolvedValueOnce({ role: 'super_admin', elevated_until: '2026-10-16T12:00:00Z' })
    const user = userEvent.setup()
    render(<AdminElevationBar admin={{ ...base, max_role: 'super_admin' }} onChanged={changed} />)
    await user.click(screen.getByRole('button', { name: 'Elevate' }))
    await user.type(screen.getByLabelText('Reason'), 'Rotate the platform IdP secret, ticket 77')
    const submit = screen.getAllByRole('button', { name: 'Elevate' }).at(-1)!
    // No elevation without a fresh code.
    expect(submit).toBeDisabled()
    await user.type(screen.getByLabelText('Code from your authenticator app'), '123456')
    await user.click(submit)
    expect(elevate).toHaveBeenCalledWith(
      'super_admin',
      30,
      'Rotate the platform IdP secret, ticket 77',
      '123456'
    )
    expect(changed).toHaveBeenCalled()
  })

  it('shows a refused code under the code field and keeps the dialog open', async () => {
    const changed = vi.fn()
    elevate.mockRejectedValueOnce(new Error('Invalid code'))
    const user = userEvent.setup()
    render(<AdminElevationBar admin={{ ...base, max_role: 'super_admin' }} onChanged={changed} />)
    await user.click(screen.getByRole('button', { name: 'Elevate' }))
    await user.type(screen.getByLabelText('Reason'), 'Rotate the platform IdP secret, ticket 77')
    await user.type(screen.getByLabelText('Code from your authenticator app'), '000000')
    await user.click(screen.getAllByRole('button', { name: 'Elevate' }).at(-1)!)
    expect(changed).not.toHaveBeenCalled()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByLabelText('Code from your authenticator app')).toHaveValue('')
  })

  it('lets a security-key holder leave the code empty, and asks for none on a key-only console', async () => {
    elevate.mockResolvedValue({ role: 'super_admin', elevated_until: '2026-10-16T12:00:00Z' })
    factors.mockReturnValue({ totp_allowed: true, webauthn_enabled: true, authenticators: [{}] })
    const user = userEvent.setup()
    const { unmount } = render(
      <AdminElevationBar admin={{ ...base, max_role: 'super_admin' }} onChanged={vi.fn()} />
    )
    await user.click(screen.getByRole('button', { name: 'Elevate' }))
    await user.type(screen.getByLabelText('Reason'), 'Rotate the platform IdP secret, ticket 77')
    await user.click(screen.getAllByRole('button', { name: 'Elevate' }).at(-1)!)
    expect(elevate).toHaveBeenLastCalledWith('super_admin', 30, expect.any(String), '')
    unmount()

    factors.mockReturnValue({ totp_allowed: false, webauthn_enabled: true, authenticators: [{}] })
    render(<AdminElevationBar admin={{ ...base, max_role: 'super_admin' }} onChanged={vi.fn()} />)
    await user.click(screen.getByRole('button', { name: 'Elevate' }))
    expect(screen.queryByLabelText('Code from your authenticator app')).not.toBeInTheDocument()
    expect(screen.getByText(/confirm with your security key/)).toBeInTheDocument()
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
    // Elevated: a compact chip with the role and the end time, the full
    // sentence for screen readers.
    expect(screen.getByRole('status')).toHaveTextContent(/Acting as .+ until/)
    expect(screen.getByTestId('elevation-control')).toHaveTextContent(/until/)
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
