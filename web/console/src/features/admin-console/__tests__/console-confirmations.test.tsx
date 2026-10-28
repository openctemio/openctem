import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SSOEnforcementCard } from '../components/sso-enforcement-card'
import { PlatformIdPForm } from '../components/platform-idp-form'
import { TypedAdminConfirmDialog } from '../components/type-to-confirm-field'
import { setSSOEnforcement, useSSOEnforcement } from '../api/use-admin-organizations'
import { deletePlatformIdP, savePlatformIdP } from '../api/use-platform-idp'
import type { AdminOrganization, PlatformIdP } from '../types'

vi.mock('../api/use-admin-organizations', async (orig) => ({
  ...(await orig<typeof import('../api/use-admin-organizations')>()),
  setSSOEnforcement: vi.fn().mockResolvedValue(undefined),
  useSSOEnforcement: vi.fn(),
}))
vi.mock('../api/use-platform-idp', async (orig) => ({
  ...(await orig<typeof import('../api/use-platform-idp')>()),
  deletePlatformIdP: vi.fn().mockResolvedValue(undefined),
  savePlatformIdP: vi.fn().mockResolvedValue(undefined),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const readiness = (over: Partial<Record<string, number | boolean>> = {}) => ({
  admin_sso_signin: true,
  owner_second_factor: true,
  api_keys: 3,
  connector_grants: 2,
  ...over,
})
const mockReadiness = (r: ReturnType<typeof readiness>) =>
  vi.mocked(useSSOEnforcement).mockReturnValue({
    data: { enforced: false, readiness: r },
    mutate: vi.fn(),
  } as unknown as ReturnType<typeof useSSOEnforcement>)

beforeEach(() => {
  vi.clearAllMocks()
  mockReadiness(readiness())
})

const org = (enforced: boolean) =>
  ({
    id: 'o1',
    name: 'Acme',
    saml_enabled: true,
    active_identity_providers: 1,
    sso_enforced: enforced,
  }) as unknown as AdminOrganization

describe('SSO enforcement switch', () => {
  it('turning enforcement off asks first and calls the API only after confirming', async () => {
    const user = userEvent.setup()
    render(<SSOEnforcementCard org={org(true)} canManage onChanged={vi.fn()} />)
    await user.click(screen.getByRole('switch'))
    expect(setSSOEnforcement).not.toHaveBeenCalled()
    expect(screen.getByText('Allow password sign-in for Acme?')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Allow password sign-in' }))
    await waitFor(() => expect(setSSOEnforcement).toHaveBeenCalledWith('o1', false))
  })

  it('turning enforcement on revokes existing keys and connections by default', async () => {
    const user = userEvent.setup()
    render(<SSOEnforcementCard org={org(false)} canManage onChanged={vi.fn()} />)
    expect(screen.getByText(/Revoke the 3 API keys and 2 AI connections/)).toBeInTheDocument()
    await user.click(screen.getByRole('switch'))
    await waitFor(() => expect(setSSOEnforcement).toHaveBeenCalledWith('o1', true, true))
  })

  it('unticking the box keeps them', async () => {
    const user = userEvent.setup()
    render(<SSOEnforcementCard org={org(false)} canManage onChanged={vi.fn()} />)
    await user.click(screen.getByRole('checkbox'))
    await user.click(screen.getByRole('switch'))
    await waitFor(() => expect(setSSOEnforcement).toHaveBeenCalledWith('o1', true, false))
  })

  it.each([
    ['no administrator has signed in through the identity provider', { admin_sso_signin: false }],
    ['no owner has two-factor authentication', { owner_second_factor: false }],
  ])('the switch stays off while %s', async (_n, over) => {
    mockReadiness(readiness(over))
    render(<SSOEnforcementCard org={org(false)} canManage onChanged={vi.fn()} />)
    expect(screen.getByRole('switch')).toBeDisabled()
  })
})

describe('TypedAdminConfirmDialog', () => {
  it('keeps the confirm button disabled until the name is typed', async () => {
    const user = userEvent.setup()
    const onConfirm = vi.fn().mockResolvedValue(undefined)
    render(
      <TypedAdminConfirmDialog
        open
        onOpenChange={vi.fn()}
        title="Retire shared-1?"
        description={<p>It stops.</p>}
        confirmLabel="Retire sensor"
        destructive
        typeToConfirm="shared-1"
        onConfirm={onConfirm}
      />
    )
    await user.type(screen.getByRole('textbox', { name: /reason/i }), 'Decommissioned host')
    const btn = screen.getByRole('button', { name: 'Retire sensor' })
    expect(btn).toBeDisabled()
    await user.type(screen.getByRole('textbox', { name: /shared-1/ }), 'shared-1')
    expect(btn).toBeEnabled()
  })
})

const idp = (over: Partial<PlatformIdP>): PlatformIdP =>
  ({
    configured: true,
    enabled: true,
    display_name: 'Corp SSO',
    issuer: 'https://idp.example.com',
    client_id: 'c',
    has_client_secret: true,
    redirect_uri: 'https://console.example.com/cb',
    scopes: ['openid'],
    require_idp: false,
    trusted_acr_values: [],
    trusted_amr_values: [],
    ...over,
  }) as PlatformIdP

describe('Platform identity provider', () => {
  it('removing needs the provider name typed', async () => {
    const user = userEvent.setup()
    render(<PlatformIdPForm idp={idp({})} hasBreakGlass onSaved={vi.fn()} />)
    await user.click(screen.getByRole('button', { name: 'Remove identity provider' }))
    const confirm = screen.getAllByRole('button', { name: 'Remove identity provider' }).pop()!
    expect(confirm).toBeDisabled()
    await user.type(screen.getByRole('textbox', { name: /Corp SSO/ }), 'Corp SSO')
    expect(confirm).toBeEnabled()
    await user.click(confirm)
    await waitFor(() => expect(deletePlatformIdP).toHaveBeenCalled())
  })

  it('switching "require" off asks before saving', async () => {
    const user = userEvent.setup()
    render(<PlatformIdPForm idp={idp({ require_idp: true })} hasBreakGlass onSaved={vi.fn()} />)
    const sw = screen.getAllByRole('switch').find((s) => s.getAttribute('aria-checked') === 'true')
    const requireSwitch = screen
      .getAllByRole('switch')
      .find((s) => /require/i.test(s.getAttribute('aria-label') ?? s.id))
    await user.click((requireSwitch ?? sw)!)
    await user.click(screen.getByRole('button', { name: 'Save' }))
    expect(savePlatformIdP).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Stop requiring it' }))
    await waitFor(() => expect(savePlatformIdP).toHaveBeenCalled())
  })
})
