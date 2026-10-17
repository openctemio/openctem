import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'

import { ApiClientError } from '@/lib/api/error-handler'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const fetcherWithOptions = vi.fn()
const fetcher = vi.fn()
vi.mock('@/lib/api/client', () => ({
  fetcher: (url: string) => fetcher(url),
  fetcherWithOptions: (url: string, init: RequestInit) => fetcherWithOptions(url, init),
}))

let role: 'owner' | 'admin' | 'member' = 'member'
vi.mock('@/lib/permissions', () => ({
  usePermissions: () => ({
    isAtLeast: (r: string) =>
      r === 'admin' ? role === 'owner' || role === 'admin' : r === 'member' || role !== 'member',
    isOwner: () => role === 'owner',
    isLoading: false,
  }),
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

import { GrantSupportDialog } from '../components/grant-support-dialog'
import { SupportAccessBanner } from '../components/support-access-banner'
import { SupportAccessSettings } from '../components/support-access-settings'

function withSWR(ui: React.ReactNode) {
  return <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>
}

const FUTURE = new Date(Date.now() + 3 * 3600_000).toISOString()

describe('GrantSupportDialog', () => {
  beforeEach(() => vi.clearAllMocks())

  async function fill(user: ReturnType<typeof userEvent.setup>) {
    await user.type(screen.getByLabelText(/support administrator/i), 'help@platform.test')
    await user.type(screen.getByLabelText(/^reason$/i), 'Scan results look wrong for asset X')
  }

  it('validates before sending and needs at least one scope', async () => {
    const user = userEvent.setup()
    render(<GrantSupportDialog open onOpenChange={vi.fn()} onGranted={vi.fn()} />)
    await user.type(screen.getByLabelText(/^reason$/i), 'short')
    await user.click(screen.getByRole('button', { name: 'Grant access' }))
    expect(fetcherWithOptions).not.toHaveBeenCalled()
    expect(screen.getByText(/enter the support administrator/i)).toBeInTheDocument()
    expect(screen.getByText('Write 10 to 500 characters.')).toBeInTheDocument()

    await user.click(screen.getByRole('checkbox', { name: 'Findings' }))
    await user.click(screen.getByRole('checkbox', { name: 'Assets' }))
    expect(screen.getByText('Choose at least one.')).toBeInTheDocument()
    expect(screen.getByText('5/500')).toBeInTheDocument()
  })

  it('sends the grant with both scopes and 4 hours by default', async () => {
    const user = userEvent.setup()
    const onGranted = vi.fn()
    const onOpenChange = vi.fn()
    fetcherWithOptions.mockResolvedValue({ id: 'g1' })
    render(<GrantSupportDialog open onOpenChange={onOpenChange} onGranted={onGranted} />)
    await fill(user)
    await user.type(screen.getByLabelText(/case reference/i), 'CASE-42')
    await user.click(screen.getByRole('button', { name: 'Grant access' }))
    await waitFor(() => expect(onGranted).toHaveBeenCalled())
    const [url, init] = fetcherWithOptions.mock.calls[0]
    expect(url).toBe('/api/v1/organization/support-access/grants')
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body)).toEqual({
      admin_email: 'help@platform.test',
      scopes: ['findings', 'assets'],
      duration_hours: 4,
      reason: 'Scan results look wrong for asset X',
      case_ref: 'CASE-42',
    })
    expect(onOpenChange).toHaveBeenCalledWith(false)
  })

  it('keeps the form open with the reason when re-authentication is not completed', async () => {
    const user = userEvent.setup()
    const onGranted = vi.fn()
    // The shared client already showed the re-auth dialog; the user closed it.
    fetcherWithOptions.mockRejectedValue(
      new ApiClientError('Confirm your identity to continue', 'STEP_UP_REQUIRED', 403)
    )
    render(<GrantSupportDialog open onOpenChange={vi.fn()} onGranted={onGranted} />)
    await fill(user)
    await user.click(screen.getByRole('button', { name: 'Grant access' }))
    expect(await screen.findByRole('alert')).toBeInTheDocument()
    expect(onGranted).not.toHaveBeenCalled()
    expect(screen.getByLabelText(/^reason$/i)).toHaveValue('Scan results look wrong for asset X')
  })

  it('shows the server refusal (not a support administrator, already active)', async () => {
    const user = userEvent.setup()
    fetcherWithOptions.mockRejectedValue(
      new ApiClientError('A grant for this administrator is already active', 'CONFLICT', 409)
    )
    render(<GrantSupportDialog open onOpenChange={vi.fn()} onGranted={vi.fn()} />)
    await fill(user)
    await user.click(screen.getByRole('button', { name: 'Grant access' }))
    expect(await screen.findByRole('alert')).toBeInTheDocument()
  })
})

const GRANTS = [
  {
    id: 'g1',
    admin_email: 'help@platform.test',
    admin_name: 'Hana Support',
    level: 'read',
    scopes: ['findings', 'assets'],
    reason: 'Scan results look wrong',
    case_ref: 'CASE-42',
    starts_at: '2026-10-16T08:00:00Z',
    expires_at: FUTURE,
    created_at: '2026-10-16T08:00:00Z',
    active: true,
    session_count: 2,
    open_session: true,
    last_access_at: '2026-10-16T09:00:00Z',
  },
  {
    id: 'g0',
    admin_email: 'old@platform.test',
    admin_name: 'Old Support',
    level: 'read',
    scopes: ['findings'],
    reason: 'Earlier case',
    starts_at: '2026-10-01T08:00:00Z',
    expires_at: '2026-10-01T12:00:00Z',
    revoked_at: '2026-10-01T09:00:00Z',
    created_at: '2026-10-01T08:00:00Z',
    active: false,
    session_count: 0,
    open_session: false,
  },
]

describe('SupportAccessSettings', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    fetcher.mockResolvedValue({ data: GRANTS })
  })

  it('lists active access and history; an admin can revoke but not grant', async () => {
    const user = userEvent.setup()
    fetcherWithOptions.mockResolvedValue({ ...GRANTS[0], active: false })
    render(withSWR(<SupportAccessSettings canRead isOwner={false} />))
    const active = await screen.findByTestId('support-active-grant')
    expect(within(active).getByText('Viewing now')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Grant access' })).not.toBeInTheDocument()

    const rows = screen.getAllByTestId('support-grant-row')
    expect(rows).toHaveLength(2)
    expect(within(rows[1]).getByText('Revoked')).toBeInTheDocument()
    expect(within(rows[1]).getByText('Never')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /audit log/i })).toHaveAttribute(
      'href',
      '/settings/audit-log?q=support.'
    )

    await user.click(within(active).getByRole('button', { name: 'Revoke' }))
    await user.click(await screen.findByRole('button', { name: 'Revoke access' }))
    await waitFor(() =>
      expect(fetcherWithOptions).toHaveBeenCalledWith(
        '/api/v1/organization/support-access/grants/g1',
        { method: 'DELETE' }
      )
    )
  })

  it('an owner sees Grant access', async () => {
    render(withSWR(<SupportAccessSettings canRead isOwner />))
    expect(await screen.findByRole('button', { name: 'Grant access' })).toBeInTheDocument()
  })

  it('a member reads nothing and is told why', () => {
    render(withSWR(<SupportAccessSettings canRead={false} isOwner={false} />))
    expect(fetcher).not.toHaveBeenCalled()
    expect(screen.getByText(/only owners and admins/i)).toBeInTheDocument()
  })
})

describe('SupportAccessBanner', () => {
  beforeEach(() => vi.clearAllMocks())

  it('renders nothing when no support access is active', async () => {
    role = 'member'
    fetcher.mockResolvedValue({ data: [] })
    const { container } = render(withSWR(<SupportAccessBanner />))
    await waitFor(() =>
      expect(fetcher).toHaveBeenCalledWith('/api/v1/organization/support-access/active')
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('tells a member who can view what, until when, with no manage link', async () => {
    role = 'member'
    fetcher.mockResolvedValue({
      data: [
        {
          admin_name: 'Hana Support',
          scopes: ['findings', 'assets'],
          expires_at: FUTURE,
          open_session: false,
          case_ref: 'CASE-42',
        },
      ],
    })
    render(withSWR(<SupportAccessBanner />))
    const banner = await screen.findByTestId('support-access-banner')
    expect(banner).toHaveAttribute('data-viewing', 'false')
    expect(banner).toHaveTextContent(
      'Platform support (Hana Support) can view your findings and assets'
    )
    expect(banner).toHaveTextContent('(case CASE-42)')
    expect(within(banner).queryByRole('link')).not.toBeInTheDocument()
  })

  it('stresses an open session and links owners and admins to the page', async () => {
    role = 'admin'
    fetcher.mockResolvedValue({
      data: [
        { admin_name: 'Hana Support', scopes: ['assets'], expires_at: FUTURE, open_session: true },
      ],
    })
    render(withSWR(<SupportAccessBanner />))
    const banner = await screen.findByTestId('support-access-banner')
    expect(banner).toHaveAttribute('data-viewing', 'true')
    expect(banner).toHaveAttribute('role', 'alert')
    expect(banner).toHaveTextContent('is viewing your assets now')
    expect(within(banner).getByRole('link', { name: 'Manage support access' })).toHaveAttribute(
      'href',
      '/settings/support-access'
    )
  })
})
