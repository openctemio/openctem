import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { dayBound } from '../lib/audit-range'
import { endAdminSession, useAdminSessions } from '../api/use-admin-sessions'
import type { AdminConsoleSession, AdminIdentity } from '../types'
import SessionsPage from '@console/app/(console)/security/sessions/page'

const mocks = vi.hoisted(() => ({ admin: { current: null as AdminIdentity | null } }))

vi.mock('../components/admin-console-shell', () => ({
  useAdmin: () => mocks.admin.current,
  useAdminOrNull: () => mocks.admin.current,
}))
vi.mock('../api/use-admin-sessions', () => ({
  useAdminSessions: vi.fn(),
  endAdminSession: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('next/navigation', () => ({ usePathname: () => '/security/sessions' }))

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
    expect(screen.getByText(/platform roles do not include this/i)).toBeInTheDocument()
  })

  it('offers Review only for a break-glass session that is not this one', async () => {
    vi.mocked(useAdminSessions).mockReturnValue({
      data: {
        data: [session({ id: 'mine', current: true, break_glass: true }), session({ id: 'b' })],
      },
      error: undefined,
      isLoading: false,
      mutate: vi.fn(),
    } as unknown as ReturnType<typeof useAdminSessions>)
    await renderPage('super_admin')
    expect(screen.queryByRole('link', { name: 'Review' })).toBeNull()
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
    // The mark of the own session is plain text beside the name, not a badge
    // that squeezes the name column; the address is the part that gives way.
    const mark = screen.getAllByText('This session')[0]
    expect(mark.closest('[data-slot="badge"]')).toBeNull()
    const nameCell = mark.parentElement!
    expect(nameCell.firstElementChild).toHaveClass('min-w-0', 'truncate')
    // Break-glass is a mark of the name, plain text, not a badge in the Role column.
    const breakGlass = screen.getAllByText('Emergency access')[0]
    expect(breakGlass.closest('[data-slot="badge"]')).toBeNull()
    expect(breakGlass.parentElement!.textContent).toContain('Ops')
    const address = within(breakGlass.parentElement!).getByText('ops@op.test')
    expect(address).toHaveClass('min-w-0', 'shrink-[4]', 'truncate')
    // An open break-glass session is the page's main action: review what it did.
    expect(screen.getByRole('link', { name: 'Review' })).toHaveAttribute(
      'href',
      '/security/activity?kind=all&admin_email=ops%40op.test'
    )
    // The list says its count once and names its table.
    expect(document.querySelectorAll('[data-slot="list-count"]')).toHaveLength(1)
    expect(screen.getByRole('table', { name: 'Sessions' })).toBeInTheDocument()
    // One session can be ended, from its row's menu; the current session's row has no menu.
    const menus = screen.getAllByRole('button', { name: /^Actions for the session of/ })
    expect(menus).toHaveLength(1)
    expect(menus[0]).toHaveAccessibleName('Actions for the session of ops@op.test')
    for (const badge of screen.getAllByText('This session')) {
      const row = badge.closest('tr')
      if (row) expect(within(row).queryByRole('button', { name: /^Actions for/ })).toBeNull()
    }
    await user.click(menus[0])
    // Ending is the only action, and nothing happens before the confirmation.
    const items = await screen.findAllByRole('menuitem')
    expect(items.map((i) => i.textContent)).toEqual(['End session'])
    await user.click(items[0])
    expect(endAdminSession).not.toHaveBeenCalled()

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
