import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const mocks = vi.hoisted(() => ({
  session: {
    admin: null as Record<string, unknown> | null,
    mutate: vi.fn(),
  },
}))

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('next/navigation', () => ({
  usePathname: () => '/organizations',
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
}))
vi.mock('../api/use-admin-session', () => ({
  useAdminSession: () => ({
    admin: mocks.session.admin,
    isLoading: false,
    error: undefined,
    mutate: mocks.session.mutate,
  }),
  adminLogout: vi.fn(),
}))
vi.mock('@/features/auth/actions/local-auth-actions', () => ({ localLogoutAction: vi.fn() }))

import { adminFetch } from '@console/lib/admin-api/client'
import { SecurityKeysPanel } from '../components/security-keys-panel'
import { ConsoleMfaPolicyCard } from '../components/console-mfa-policy-card'
import { AdminConsoleShell } from '../components/admin-console-shell'
import { AdminConfirmDialog } from '../components/admin-confirm-dialog'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const KEY = (id: string, name: string, extra: Record<string, unknown> = {}) => ({
  id,
  name,
  transports: ['usb'],
  synced: false,
  sync_capable: false,
  created_at: '2026-10-01T00:00:00Z',
  ...extra,
})

const BASE = {
  webauthn_enabled: true,
  authenticators: [] as unknown[],
  recovery_codes_left: 0,
  totp_enabled: true,
  totp_allowed: true,
  require_webauthn: false,
  enrollment_required: false,
  min_authenticators: 2,
  max_authenticators: 10,
}

type Call = { url: string; method: string; body?: unknown }
let calls: Call[] = []
let factors: Record<string, unknown> = BASE
let answers: Record<string, () => Response> = {}

const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status })

function route(url: string, init: RequestInit = {}): Response {
  const method = init.method ?? 'GET'
  const path = url.replace('/api/v1/admin', '')
  calls.push({ url: path, method, body: init.body })
  const custom = answers[`${method} ${path}`]
  if (custom) return custom()
  if (path === '/auth/factors') return json(factors)
  return json({})
}

const credCreate = vi.fn()

function wrap(children: ReactNode) {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{children}</SWRConfig>
  )
}

beforeEach(() => {
  calls = []
  answers = {}
  factors = BASE
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string, init?: RequestInit) => Promise.resolve(route(url, init)))
  )
  vi.stubGlobal('PublicKeyCredential', function PublicKeyCredential() {})
  Object.defineProperty(navigator, 'credentials', {
    configurable: true,
    value: { get: vi.fn(), create: credCreate },
  })
  credCreate.mockReset()
  mocks.session.mutate.mockReset()
})
afterEach(() => vi.unstubAllGlobals())

describe('My security keys', () => {
  it('lists keys with the synced badge and the policy guidance', async () => {
    factors = {
      ...BASE,
      authenticators: [
        KEY('k1', 'Blue key', { last_used_at: '2026-10-10T00:00:00Z' }),
        KEY('k2', 'Laptop', { synced: true }),
      ],
      recovery_codes_left: 7,
    }
    wrap(<SecurityKeysPanel />)
    expect(await screen.findByText('Blue key')).toBeInTheDocument()
    expect(screen.getByText('Synced passkey')).toBeInTheDocument()
    expect(screen.getByText('Device-bound')).toBeInTheDocument()
    expect(screen.getByText(/Never used/)).toBeInTheDocument()
    expect(screen.getByText(/Register at least 2 keys/)).toBeInTheDocument()
    expect(screen.getByText('Security keys: 2 of 2')).toBeInTheDocument()
    expect(screen.getByTestId('recovery-codes-left')).toHaveTextContent('7 unused codes left.')
  })

  it('adds a key: name, then the browser ceremony, then the answer', async () => {
    const user = userEvent.setup()
    answers['POST /auth/webauthn/credentials/options'] = () =>
      json({
        publicKey: {
          rp: { id: 'admin.example.com', name: 'Console' },
          user: { id: 'AQ', name: 'a@example.com', displayName: 'A' },
          challenge: 'AgM',
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        },
      })
    answers['POST /auth/webauthn/credentials'] = () => {
      factors = { ...BASE, authenticators: [KEY('k1', 'Blue key')] }
      return json(KEY('k1', 'Blue key'), 201)
    }
    credCreate.mockResolvedValueOnce({ toJSON: () => ({ id: 'new-cred' }) })

    wrap(<SecurityKeysPanel />)
    await user.click(await screen.findByRole('button', { name: 'Add security key' }))
    await user.type(screen.getByLabelText('Name'), 'Blue key')
    await user.click(screen.getByRole('button', { name: 'Continue' }))

    expect(await screen.findByText('Blue key')).toBeInTheDocument()
    const finish = calls.find((c) => c.method === 'POST' && c.url === '/auth/webauthn/credentials')
    expect(finish?.body).toBe(JSON.stringify({ name: 'Blue key', credential: { id: 'new-cred' } }))
    const userId = credCreate.mock.calls[0][0].publicKey.user.id as ArrayBuffer
    expect(new Uint8Array(userId)).toEqual(new Uint8Array([1]))
  })

  it('removing below the floor shows the refusal and keeps the key', async () => {
    const user = userEvent.setup()
    factors = {
      ...BASE,
      require_webauthn: true,
      authenticators: [KEY('k1', 'Blue key'), KEY('k2', 'Laptop')],
      recovery_codes_left: 5,
    }
    answers['DELETE /auth/webauthn/credentials/k1'] = () =>
      json({ code: 'WEBAUTHN_KEEP_REQUIRED', message: 'keep two' }, 409)

    wrap(<SecurityKeysPanel />)
    await user.click(await screen.findByRole('button', { name: 'Remove Blue key' }))
    const dialog = await screen.findByRole('alertdialog').catch(() => screen.getByRole('dialog'))
    await user.click(within(dialog).getByRole('button', { name: 'Remove key' }))
    expect(
      await screen.findByText(/requires at least two security keys. Register a replacement/)
    ).toBeInTheDocument()
    expect(screen.getByText('Blue key')).toBeInTheDocument()
  })

  it('removes a key above the floor', async () => {
    const user = userEvent.setup()
    factors = {
      ...BASE,
      authenticators: [KEY('k1', 'Blue key'), KEY('k2', 'Laptop'), KEY('k3', 'Spare')],
    }
    answers['DELETE /auth/webauthn/credentials/k3'] = () => {
      factors = { ...BASE, authenticators: [KEY('k1', 'Blue key'), KEY('k2', 'Laptop')] }
      return new Response(null, { status: 204 })
    }
    wrap(<SecurityKeysPanel />)
    await user.click(await screen.findByRole('button', { name: 'Remove Spare' }))
    await user.click(await screen.findByRole('button', { name: 'Remove key' }))
    await waitFor(() => expect(screen.queryByText('Spare')).not.toBeInTheDocument())
  })

  it('shows new recovery codes once and closes only after the acknowledgement', async () => {
    const user = userEvent.setup()
    const codes = ['aaaa-bbbb-cccc', 'dddd-eeee-ffff']
    answers['POST /auth/recovery-codes'] = () => {
      factors = { ...BASE, recovery_codes_left: 2 }
      return json({ codes })
    }
    wrap(<SecurityKeysPanel />)
    await user.click(await screen.findByRole('button', { name: 'Generate recovery codes' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('aaaa-bbbb-cccc')).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: 'Copy' })).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: 'Download .txt' })).toBeInTheDocument()
    const done = within(dialog).getByRole('button', { name: 'Done' })
    expect(done).toBeDisabled()
    await user.keyboard('{Escape}')
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    await user.click(within(dialog).getByRole('checkbox'))
    await user.click(done)
    await waitFor(() => expect(screen.queryByText('aaaa-bbbb-cccc')).not.toBeInTheDocument())
    expect(screen.getByTestId('recovery-codes-left')).toHaveTextContent('2 unused codes left.')
  })

  it('shows the grace deadline to an administrator without a key under the policy', async () => {
    factors = { ...BASE, require_webauthn: true, webauthn_grace_until: '2030-01-01T00:00:00Z' }
    wrap(<SecurityKeysPanel />)
    expect(await screen.findByText(/Register a key before/)).toBeInTheDocument()
  })
  it('shows no deadline once the administrator holds a key', async () => {
    factors = {
      ...BASE,
      require_webauthn: true,
      webauthn_grace_until: '2030-01-01T00:00:00Z',
      authenticators: [KEY('k1', 'Blue key')],
    }
    wrap(<SecurityKeysPanel />)
    expect(await screen.findByText('Blue key')).toBeInTheDocument()
    expect(screen.queryByText(/Register a key before/)).not.toBeInTheDocument()
  })
  it('explains when the console has no relying party', async () => {
    factors = { ...BASE, webauthn_enabled: false }
    wrap(<SecurityKeysPanel />)
    expect(await screen.findByText('Security keys are not available')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Add security key' })).toBeDisabled()
  })
})

describe('enrollment gate', () => {
  it('shows only the security keys while the session is held on enrollment', async () => {
    factors = { ...BASE, require_webauthn: true, enrollment_required: true }
    mocks.session.admin = {
      id: 'a1',
      email: 'ops@example.com',
      name: 'Ops',
      role: 'ops_admin',
      factor_enrollment_required: true,
    }
    wrap(
      <AdminConsoleShell>
        <p>console page</p>
      </AdminConsoleShell>
    )
    expect(await screen.findByText('Register your security keys to continue')).toBeInTheDocument()
    expect(screen.getByText(/ops@example.com needs at least two keys/)).toBeInTheDocument()
    expect(await screen.findByRole('button', { name: 'Add security key' })).toBeInTheDocument()
    expect(screen.queryByText('console page')).not.toBeInTheDocument()
  })

  it('a FACTOR_ENROLLMENT_REQUIRED refusal re-reads the session', async () => {
    mocks.session.admin = { id: 'a1', email: 'ops@example.com', name: 'Ops', role: 'ops_admin' }
    answers['GET /overview'] = () =>
      json({ code: 'FACTOR_ENROLLMENT_REQUIRED', message: 'enroll' }, 403)
    wrap(
      <AdminConsoleShell>
        <p>console page</p>
      </AdminConsoleShell>
    )
    expect(await screen.findByText('console page')).toBeInTheDocument()
    await adminFetch('/overview').catch(() => undefined)
    expect(mocks.session.mutate).toHaveBeenCalled()
  })
})

describe('Require security keys (policy)', () => {
  it('is disabled with an explanation when the console address is not set', async () => {
    answers['GET /settings/console-mfa'] = () =>
      json({ require_webauthn: false, version: 1, webauthn_enabled: false })
    wrap(<ConsoleMfaPolicyCard />)
    expect(await screen.findByText(/ADMIN_PUBLIC_URL/)).toBeInTheDocument()
    expect(screen.getByRole('switch')).toBeDisabled()
  })

  it('turns it on with the version read and shows the compliance refusal', async () => {
    const user = userEvent.setup()
    answers['GET /settings/console-mfa'] = () =>
      json({ require_webauthn: false, version: 4, webauthn_enabled: true })
    answers['PUT /settings/console-mfa'] = () =>
      json({ code: 'MFA_POLICY_ACTOR_NOT_COMPLIANT', message: 'not compliant' }, 409)
    wrap(<ConsoleMfaPolicyCard />)
    await user.click(await screen.findByRole('switch'))
    await user.click(await screen.findByRole('button', { name: 'Confirm' }))
    expect(
      await screen.findByText(/Register at least two security keys and generate recovery codes/)
    ).toBeInTheDocument()
    const put = calls.find((c) => c.method === 'PUT')
    expect(put?.body).toBe(JSON.stringify({ require_webauthn: true, version: 4 }))
  })
})

describe('forms that carry the authenticator code', () => {
  const dialog = (onConfirm: () => Promise<void>) => (
    <AdminConfirmDialog
      open
      onOpenChange={vi.fn()}
      title="End the session?"
      description="It signs out."
      confirmLabel="End session"
      requireCode
      onConfirm={onConfirm}
    />
  )

  it('let the code stay empty when the administrator holds a key', async () => {
    const user = userEvent.setup()
    factors = { ...BASE, authenticators: [KEY('k1', 'Blue key')] }
    const onConfirm = vi.fn().mockResolvedValue(undefined)
    wrap(dialog(onConfirm))
    expect(
      await screen.findByText(/leave it empty to confirm with your security key/)
    ).toBeInTheDocument()
    await user.type(screen.getByLabelText('Reason'), 'support case 4411')
    await user.click(screen.getByRole('button', { name: 'End session' }))
    expect(onConfirm).toHaveBeenCalledWith({ reason: 'support case 4411', totp_code: '' })
  })

  it('still need the code from an administrator without a key', async () => {
    const user = userEvent.setup()
    const onConfirm = vi.fn()
    wrap(dialog(onConfirm))
    await user.type(await screen.findByLabelText('Reason'), 'support case 4411')
    await waitFor(() => expect(calls.some((c) => c.url === '/auth/factors')).toBe(true))
    expect(screen.getByRole('button', { name: 'End session' })).toBeDisabled()
    expect(screen.queryByText(/leave it empty/)).not.toBeInTheDocument()
  })
})
