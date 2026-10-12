import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { dayBound } from '../lib/audit-range'
import { endAdminSession, useAdminSessions } from '../api/use-admin-sessions'
import type { AdminConsoleSession, AdminIdentity } from '../types'
import SessionsPage from '@/app/(admin-console)/admin/(console)/security/sessions/page'

const mocks = vi.hoisted(() => ({ admin: { current: null as AdminIdentity | null } }))

vi.mock('../components/admin-console-shell', () => ({ useAdmin: () => mocks.admin.current }))
vi.mock('../api/use-admin-sessions', () => ({
  useAdminSessions: vi.fn(),
  endAdminSession: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('next/navigation', () => ({ usePathname: () => '/admin/security/sessions' }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

function session(patch: Partial<AdminConsoleSession>): AdminConsoleSession {
  return {
    id: 's1',
    admin_id: 'a1',
    admin_email: 'me@op.test',
    admin_name: 'Me',
    admin_role: 'super_admin',
    break_glass: false,
    auth_method: 'password',
    mfa_verified: true,
    ip_address: '198.51.100.7',
    created_at: '2026-10-08T08:00:00Z',
    last_seen_at: '2026-10-08T09:00:00Z',
    expires_at: '2026-10-08T20:00:00Z',
    current: false,
    ...patch,
  }
}

async function renderPage(role: AdminIdentity['role']) {
  mocks.admin.current = { id: 'a1', email: 'me@op.test', name: 'Me', role }
  return render(<SessionsPage />)
}

describe('dayBound', () => {
  it('turns a date into the start of that day, or of the next for "to"', () => {
    const from = dayBound('2026-10-08', false)!
    const to = dayBound('2026-10-08', true)!
    expect(new Date(to).getTime() - new Date(from).getTime()).toBe(24 * 3600 * 1000)
  })
  it('ignores anything that is not a date', () => {
    expect(dayBound('', false)).toBeUndefined()
    expect(dayBound('2026-13-45x', true)).toBeUndefined()
    expect(dayBound("2026-10-08' OR 1=1", true)).toBeUndefined()
  })
})

describe('Sessions page', () => {
  beforeEach(() => vi.clearAllMocks())

  it('is for super admins only (no request otherwise)', async () => {
    vi.mocked(useAdminSessions).mockReturnValue({
      data: undefined,
      error: undefined,
      isLoading: false,
      mutate: vi.fn(),
    } as unknown as ReturnType<typeof useAdminSessions>)
    await renderPage('ops_admin')
    expect(useAdminSessions).toHaveBeenCalledWith(false)
    expect(screen.getByText(/only a super admin/i)).toBeInTheDocument()
  })

  it('cannot end the current session, and ends another with a reason and a code', async () => {
    const user = userEvent.setup()
    const mutate = vi.fn()
    vi.mocked(useAdminSessions).mockReturnValue({
      data: {
        data: [
          session({ id: 'mine', current: true }),
          session({
            id: 'theirs',
            admin_id: 'a2',
            admin_email: 'ops@op.test',
            admin_name: 'Ops',
            admin_role: 'ops_admin',
            break_glass: true,
          }),
        ],
      },
      error: undefined,
      isLoading: false,
      mutate,
    } as unknown as ReturnType<typeof useAdminSessions>)
    vi.mocked(endAdminSession).mockResolvedValue(undefined)
    await renderPage('super_admin')

    expect(screen.getAllByText('This session').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Break-glass').length).toBeGreaterThan(0)
    // One session can be ended; End is never in the current session's row.
    const ends = screen.getAllByRole('button', { name: /^end$/i })
    expect(ends).toHaveLength(1)
    for (const badge of screen.getAllByText('This session')) {
      const row = badge.closest('tr')
      if (row) expect(within(row).queryByRole('button', { name: /^end$/i })).toBeNull()
    }
    await user.click(ends[0])

    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByText(/ops@op.test is signed out/)).toBeInTheDocument()
    await user.type(within(dialog).getByLabelText(/^reason$/i), 'Laptop reported stolen')
    await user.type(within(dialog).getByLabelText(/code from your authenticator/i), '654321')
    await user.click(within(dialog).getByRole('button', { name: 'End session' }))
    await waitFor(() =>
      expect(endAdminSession).toHaveBeenCalledWith('theirs', {
        reason: 'Laptop reported stolen',
        totp_code: '654321',
      })
    )
    await waitFor(() => expect(mutate).toHaveBeenCalled())
  })
})
