import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const adminFetch = vi.fn()
vi.mock('../api/admin-client', async (orig) => {
  const actual = await orig<typeof import('../api/admin-client')>()
  return {
    ...actual,
    adminFetch: (path: string, init?: unknown) => adminFetch(path, init),
    adminFetcher: (path: string) => adminFetch(path, undefined),
  }
})

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

import { AdminApiError } from '../api/admin-client'
import { SupportAccessPanel } from '../components/support-access-panel'

const FUTURE = new Date(Date.now() + 3 * 3600_000).toISOString()

function grant(scopes: string[]) {
  return {
    id: 'g1',
    tenant_id: 't-1',
    tenant_name: 'Acme Corp',
    scopes,
    reason: 'Scan results look wrong',
    case_ref: 'CASE-42',
    expires_at: FUTURE,
    open_session: false,
  }
}

const FINDINGS = {
  total: 1,
  data: [
    {
      id: 'f1',
      title: 'Outdated TLS',
      severity: 'high',
      status: 'new',
      source: 'dast',
      tool_name: 'nuclei',
      rule_id: 'tls-version',
      cwe_ids: ['CWE-326'],
      asset_name: 'api.acme.test',
    },
  ],
}

type Route = (path: string, init?: { method?: string; body?: unknown }) => unknown

function route(scopes: string[], findings: Route = () => FINDINGS) {
  adminFetch.mockImplementation(async (path: string, init?: { method?: string }) => {
    if (path === '/support/grants') return { data: [grant(scopes)] }
    if (path === '/support/grants/g1/sessions' && init?.method === 'POST') {
      return { id: 's1', grant_id: 'g1', tenant_id: 't-1', scopes, expires_at: FUTURE }
    }
    if (path === '/support/sessions/s1/overview') {
      return {
        tenant_name: 'Acme Corp',
        asset_count: 12,
        open_finding_count: 3,
        open_findings_by_severity: { high: 3 },
      }
    }
    if (path.startsWith('/support/sessions/s1/findings?')) return findings(path, init)
    if (path === '/support/sessions/s1' && init?.method === 'DELETE') return undefined
    throw new Error(`unexpected ${init?.method ?? 'GET'} ${path}`)
  })
}

function renderPanel(canSupport = true) {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <SupportAccessPanel canSupport={canSupport} />
    </SWRConfig>
  )
}

async function openSession(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: 'Open support session' }))
  const dialog = await screen.findByRole('dialog')
  await user.type(within(dialog).getByLabelText(/what you will look at/i), 'Check TLS findings')
  await user.click(within(dialog).getByRole('button', { name: 'Open support session' }))
  return screen.findByTestId('support-session-frame')
}

describe('Console support access', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    window.history.replaceState(null, '', '/admin/support')
  })

  it('lists the grants naming the caller; a read-only administrator cannot open a session', async () => {
    route(['findings', 'assets'])
    renderPanel(false)
    const item = await screen.findByTestId('support-grant')
    expect(within(item).getByText('Acme Corp')).toBeInTheDocument()
    expect(within(item).getByText(/case CASE-42/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Open support session' })).not.toBeInTheDocument()
  })

  it('opens a session, reads findings, and leaves when the access ends', async () => {
    const user = userEvent.setup()
    let revoked = false
    route(['findings', 'assets'], () => {
      if (revoked) {
        throw new AdminApiError('Support access ended', 403, 'SUPPORT_GRANT_REQUIRED')
      }
      return FINDINGS
    })
    renderPanel()
    const frame = await openSession(user)

    expect(adminFetch).toHaveBeenCalledWith('/support/grants/g1/sessions', {
      method: 'POST',
      body: { reason: 'Check TLS findings' },
    })
    expect(frame).toHaveTextContent('Support session — read-only — ends')
    expect(window.location.search).toContain('session=s1')
    expect(await within(frame).findByText('12')).toBeInTheDocument()

    await user.click(within(frame).getByRole('tab', { name: 'Findings' }))
    expect(await screen.findByTestId('support-finding-row')).toHaveTextContent('Outdated TLS')
    const call = adminFetch.mock.calls.find(([p]) => String(p).includes('/findings?'))
    expect(call?.[0]).toContain('status=open')
    expect(call?.[0]).toContain('per_page=25')

    // The owner revokes: the next read is refused and the view closes.
    revoked = true
    await user.type(screen.getByRole('textbox', { name: /search by name/i }), 'tls')
    expect(await screen.findByTestId('support-access-ended')).toHaveTextContent('Access ended')
    expect(screen.queryByTestId('support-session-frame')).not.toBeInTheDocument()
    expect(window.location.search).not.toContain('session=')
  })

  it('shows only the tabs for the granted scopes', async () => {
    const user = userEvent.setup()
    route(['assets'])
    renderPanel()
    const frame = await openSession(user)
    expect(within(frame).getByRole('tab', { name: 'Overview' })).toBeInTheDocument()
    expect(within(frame).getByRole('tab', { name: 'Assets' })).toBeInTheDocument()
    expect(within(frame).queryByRole('tab', { name: 'Findings' })).not.toBeInTheDocument()
  })

  it('shows only the overview parts the grant opens', async () => {
    const user = userEvent.setup()
    route(['assets'])
    const base = adminFetch.getMockImplementation()!
    adminFetch.mockImplementation(async (path: string, init?: { method?: string }) =>
      path === '/support/sessions/s1/overview'
        ? { tenant_name: 'Acme Corp', asset_count: 12 }
        : base(path, init)
    )
    renderPanel()
    const frame = await openSession(user)
    expect(await within(frame).findByText('12')).toBeInTheDocument()
    expect(within(frame).queryByText('Open findings')).not.toBeInTheDocument()
  })

  it('ends the session on request and returns to the list', async () => {
    const user = userEvent.setup()
    route(['findings'])
    renderPanel()
    const frame = await openSession(user)
    await user.click(within(frame).getByRole('button', { name: 'End session' }))
    await waitFor(() =>
      expect(adminFetch).toHaveBeenCalledWith('/support/sessions/s1', { method: 'DELETE' })
    )
    expect(await screen.findByTestId('support-grant')).toBeInTheDocument()
    expect(screen.queryByTestId('support-access-ended')).not.toBeInTheDocument()
  })
})
