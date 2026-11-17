import { describe, expect, it, vi, beforeEach } from 'vitest'
import { act, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const update = vi.fn()
let canEdit = true
let owner = true
const settings: {
  general: object
  branding: object
  security: Record<string, unknown>
  etags: object
} = {
  general: {},
  branding: {},
  security: {
    mfa_required: true,
    mfa_required_for_admins: true,
    ip_whitelist: [],
    allowed_domains: [],
    email_verification_mode: 'auto',
    invitees: 'verified_domains',
    jit_requires_approval: true,
    require_sensor_local_policy_for_private_targets: true,
  },
  etags: {},
}

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  useCanMutate: () => canEdit,
  usePermissions: () => ({
    isOwner: () => owner,
    isAtLeast: () => true,
    isLoading: false,
  }),
}))
vi.mock('../../api/use-tenant-settings', () => ({
  useTenantSettings: () => ({ settings, isLoading: false, isError: false, mutate: vi.fn() }),
  useUpdateSecuritySettings: () => ({ updateSecuritySettings: update, isUpdating: false }),
}))
vi.mock('../last-changed', () => ({ LastChanged: () => null }))
vi.mock('../personal-accounts-card', () => ({
  PersonalAccountsCard: () => <div id="personal-accounts" />,
}))
vi.mock('../domain-signup-policies', () => ({ DomainSignupPolicies: () => <p>domain rules</p> }))
vi.mock('../trusted-organizations', () => ({
  TrustedOrganizations: () => <div id="trusted-organizations">trusts</div>,
}))
vi.mock('@/features/sso-approvals/components/sso-change-approvals', () => ({
  SSOChangeApprovals: () => <p>sso changes list</p>,
}))
let ssoChanges: { id: string }[] = []
vi.mock('@/features/sso-approvals/api/use-sso-changes', () => ({
  useSSOChanges: () => ({ data: { changes: ssoChanges } }),
}))
vi.mock('@/features/sso/components/sso-managed-by-platform', () => ({
  SsoManagedNotice: () => null,
}))

import { SignInSettings, TAB_FIELDS, SIGN_IN_FIELDS } from '../sign-in-settings'

function open(search = '', hash = '') {
  window.history.replaceState(null, '', `/settings/sign-in${search ? `?${search}` : ''}${hash}`)
  return render(<SignInSettings />)
}

async function toTab(name: 'Sign-in' | 'Joining') {
  await userEvent.setup().click(screen.getByRole('tab', { name: new RegExp(`^${name}`) }))
}

describe('Settings › Sign-in', () => {
  beforeEach(() => {
    update.mockReset()
    update.mockResolvedValue(undefined)
    canEdit = true
    owner = true
    ssoChanges = []
  })

  it('splits the twelve fields between the two tabs, each exactly once', () => {
    const all = [...TAB_FIELDS['sign-in'], ...TAB_FIELDS.joining]
    expect(new Set(all).size).toBe(all.length)
    expect([...all].sort()).toEqual([...SIGN_IN_FIELDS].sort())
  })

  it('holds sign-in settings only: the sensor scan-job controls live on their own page', () => {
    open()
    expect(screen.getByLabelText('Require for everyone')).toBeInTheDocument()
    expect(screen.queryByText(/sensor-local policy/i)).toBeNull()
    expect(screen.getByRole('link', { name: 'Sensor job safety' })).toHaveAttribute(
      'href',
      '/settings/scanning/sensor-safety'
    )
  })

  it('shows two tabs, Sign-in first', () => {
    open()
    const tabs = within(screen.getByRole('tablist')).getAllByRole('tab')
    expect(tabs.map((t) => t.textContent)).toEqual(['Sign-in', 'Joining'])
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true')
  })

  it('shows the platform two-factor floor and locks the switches below it', () => {
    const base = { ...settings.security }
    try {
      settings.security = {
        ...base,
        mfa_required: false,
        mfa_required_for_admins: true,
        platform_mfa_floor: 'admins',
      }
      const { unmount } = open()
      expect(screen.getByTestId('mfa-platform-floor')).toHaveTextContent(/privileged role/)
      expect(screen.getByLabelText('Require for owners and administrators')).toBeDisabled()
      expect(screen.getByLabelText('Require for everyone')).not.toBeDisabled()
      unmount()

      settings.security = {
        ...base,
        mfa_required: true,
        mfa_required_for_admins: true,
        platform_mfa_floor: 'everyone',
      }
      open()
      expect(screen.getByTestId('mfa-platform-floor')).toHaveTextContent(/every member/)
      expect(screen.getByLabelText('Require for everyone')).toBeDisabled()
    } finally {
      settings.security = base
    }
  })

  it('renders the search anchors of each tab', async () => {
    const { container } = open()
    for (const id of ['two-factor', 're-verification', 'email-verification', 'ip-allowlist']) {
      expect(container.querySelector(`#${id}`), id).not.toBeNull()
    }
    await toTab('Joining')
    for (const id of [
      'sso-member-approval',
      'allowed-domains',
      'invitations',
      'personal-accounts',
      'domains',
      'trusted-organizations',
      'sso-approvals',
    ]) {
      expect(container.querySelector(`#${id}`), id).not.toBeNull()
    }
  })

  it('opens the Joining tab for ?tab=domains and for a Joining anchor in the hash', async () => {
    const first = open('tab=domains')
    expect(screen.getByRole('tab', { name: 'Joining' })).toHaveAttribute('aria-selected', 'true')
    first.unmount()
    open('', '#allowed-domains')
    await act(async () => {
      await new Promise((r) => setTimeout(r, 5))
    })
    expect(screen.getByRole('tab', { name: 'Joining' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByLabelText('Allowed email domains')).toBeInTheDocument()
  })

  it('confirms before saving a change that weakens sign-in, then saves only sign-in fields', async () => {
    open()
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

  it('each tab saves its own fields with the other tab at its saved values, and keeps the other tab unsaved', async () => {
    open()
    await toTab('Joining')
    // A Joining change: approval of new SSO members off.
    fireEvent.click(screen.getByLabelText('Approve new SSO members'))
    expect(screen.getByText('1 unsaved change')).toBeInTheDocument()
    await toTab('Sign-in')
    // The Joining change is kept and marked on its tab; the Sign-in tab has no bar.
    expect(screen.getByRole('tab', { name: /Joining/ })).toHaveTextContent('unsaved')
    expect(screen.queryByRole('region', { name: 'Unsaved changes' })).toBeNull()
    fireEvent.change(screen.getByLabelText('IP allowlist'), { target: { value: '10.0.0.0/8' } })
    fireEvent.click(screen.getByRole('button', { name: /save changes/i }))
    await vi.waitFor(() => expect(update).toHaveBeenCalledTimes(1))
    const body = update.mock.calls[0][0]
    expect(body.ip_whitelist).toEqual(['10.0.0.0/8'])
    // The unsaved Joining change is not sent with the Sign-in tab.
    expect(body.jit_requires_approval).toBe(true)
    expect(body.invitees).toBe('verified_domains')
    expect(Object.keys(body).sort()).toEqual([...SIGN_IN_FIELDS].sort())

    // Back on Joining, its change is still there and its bar saves it (a
    // weaker setting: confirmed first).
    await toTab('Joining')
    fireEvent.click(screen.getByRole('button', { name: /save changes/i }))
    expect(screen.getByText('New SSO members get access without approval.')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save anyway' }))
    await vi.waitFor(() => expect(update).toHaveBeenCalledTimes(2))
    const second = update.mock.calls[1][0]
    expect(second.jit_requires_approval).toBe(false)
    // The saved value of the Sign-in field, not the edit (the mock never refreshes).
    expect(second.ip_whitelist).toEqual([])
  })

  it('Discard on one tab leaves the other tab alone', async () => {
    open()
    fireEvent.change(screen.getByLabelText('IP allowlist'), { target: { value: '10.0.0.0/8' } })
    await toTab('Joining')
    fireEvent.click(screen.getByLabelText('Approve new SSO members'))
    fireEvent.click(screen.getByRole('button', { name: 'Discard' }))
    expect(screen.getByLabelText('Approve new SSO members')).toBeChecked()
    await toTab('Sign-in')
    expect(screen.getByLabelText('IP allowlist')).toHaveValue('10.0.0.0/8')
  })

  it('tells an owner how many SSO changes wait, on the Joining tab', async () => {
    ssoChanges = [{ id: 'a' }, { id: 'b' }]
    open()
    expect(screen.queryByTestId('sso-changes-banner')).toBeNull()
    await toTab('Joining')
    expect(screen.getByTestId('sso-changes-banner')).toHaveTextContent(
      '2 SSO changes wait for your decision.'
    )
  })

  it('shows no SSO banner to an administrator (owners decide)', async () => {
    owner = false
    ssoChanges = [{ id: 'a' }]
    open()
    await toTab('Joining')
    expect(screen.queryByTestId('sso-changes-banner')).toBeNull()
  })

  it('is read-only with the reason for anyone but the owner', async () => {
    canEdit = false
    open()
    expect(
      screen.getByText('Only the organization owner can change these settings.')
    ).toBeInTheDocument()
    expect(screen.getByLabelText('Require for everyone')).toBeDisabled()
    await toTab('Joining')
    expect(screen.getByLabelText('Approve new SSO members')).toBeDisabled()
    expect(screen.getByLabelText('Allowed email domains')).toBeDisabled()
  })
})
