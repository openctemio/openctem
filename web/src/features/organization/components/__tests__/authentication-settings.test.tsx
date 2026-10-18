import { describe, expect, it, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

const update = vi.fn()
let canEdit = true
const settings = {
  general: {},
  branding: {},
  security: {
    mfa_required: true,
    mfa_required_for_admins: true,
    ip_whitelist: [],
    allowed_domains: [],
    email_verification_mode: 'auto',
    require_sensor_local_policy_for_private_targets: true,
  },
  etags: {},
}

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  useCanMutate: () => canEdit,
}))
vi.mock('../../api/use-tenant-settings', () => ({
  useTenantSettings: () => ({ settings, isLoading: false, isError: false, mutate: vi.fn() }),
  useUpdateSecuritySettings: () => ({ updateSecuritySettings: update, isUpdating: false }),
}))
vi.mock('../last-changed', () => ({ LastChanged: () => null }))
vi.mock('../personal-accounts-card', () => ({ PersonalAccountsCard: () => <div /> }))
vi.mock('../invitation-policy-card', () => ({ InvitationPolicyCard: () => <div /> }))
vi.mock('@/features/sso/components/sso-managed-by-platform', () => ({
  SsoManagedNotice: () => null,
}))

import { AuthenticationSettings } from '../authentication-settings'

describe('Security › Authentication', () => {
  beforeEach(() => {
    update.mockReset()
    update.mockResolvedValue(undefined)
    canEdit = true
  })

  it('holds sign-in settings only: the sensor scan-job controls live on their own page', () => {
    render(<AuthenticationSettings />)
    expect(screen.getByLabelText('Require for everyone')).toBeInTheDocument()
    expect(screen.queryByText(/sensor-local policy/i)).toBeNull()
    expect(screen.getByRole('link', { name: 'Sensor job safety' })).toHaveAttribute(
      'href',
      '/settings/scanning/sensor-safety'
    )
    expect(screen.queryByText(/session/i)).toBeNull()
  })

  it('renders the search anchors', () => {
    const { container } = render(<AuthenticationSettings />)
    for (const id of [
      'two-factor',
      'sso-member-approval',
      'email-verification',
      'allowed-domains',
      'ip-allowlist',
      'invitations',
      'personal-accounts',
    ]) {
      expect(container.querySelector(`#${id}`), id).not.toBeNull()
    }
  })

  it('confirms before saving a change that weakens sign-in, then saves only sign-in fields', async () => {
    render(<AuthenticationSettings />)
    expect(screen.queryByRole('region', { name: 'Unsaved changes' })).toBeNull()
    fireEvent.click(screen.getByLabelText('Require for everyone'))
    fireEvent.click(screen.getByRole('button', { name: /save changes/i }))
    expect(screen.getByText('Weaken sign-in security?')).toBeInTheDocument()
    expect(
      screen.getByText('Two-factor authentication is no longer required for everyone.')
    ).toBeInTheDocument()
    expect(update).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Save anyway' }))
    await vi.waitFor(() => expect(update).toHaveBeenCalledTimes(1))
    const body = update.mock.calls[0][0]
    expect(body.mfa_required).toBe(false)
    expect(body).not.toHaveProperty('allow_sensor_interactsh')
    expect(body).not.toHaveProperty('require_sensor_local_policy_for_private_targets')
  })

  it('is read-only with the reason for anyone but the owner', () => {
    canEdit = false
    render(<AuthenticationSettings />)
    expect(
      screen.getByText('Only the organization owner can change these settings.')
    ).toBeInTheDocument()
    expect(screen.getByLabelText('Require for everyone')).toBeDisabled()
  })
})
