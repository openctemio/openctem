import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { buildAttention, STALE_COMMAND_SECONDS } from '../lib/attention'
import { visibleAdminNav } from '../lib/admin-nav-visibility'
import { AttentionQueue } from '../components/attention-queue'
import type { AdminIdentity, AdminOverview } from '../types'

const mocks = vi.hoisted(() => ({
  admin: { current: null as AdminIdentity | null },
  push: vi.fn(),
}))

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: mocks.push }),
  usePathname: () => '/admin',
}))
vi.mock('next-themes', () => ({ useTheme: () => ({ setTheme: vi.fn() }) }))
vi.mock('../components/admin-console-shell', () => ({
  useAdmin: () => mocks.admin.current,
}))
vi.mock('@/context/search-provider', () => ({
  useSearch: () => ({ open: true, setOpen: vi.fn() }),
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}
Element.prototype.scrollIntoView ??= function () {}

function overview(patch: {
  organizations?: Partial<AdminOverview['organizations']>
  security?: Partial<AdminOverview['security']>
  platform?: Partial<AdminOverview['platform']>
}): AdminOverview {
  return {
    organizations: { total: 3, without_owner: 0, without_owner_sample: [], ...patch.organizations },
    security: {
      break_glass_sign_ins_7d: 0,
      failed_admin_actions_24h: 0,
      break_glass_tests_overdue: 0,
      ...patch.security,
    },
    platform: {
      schema_version: 1333,
      schema_shipped: 1333,
      schema_dirty: false,
      schema_known: true,
      platform_sensors: { total: 0, online: 0, offline: 0 },
      commands_pending: 0,
      command_oldest_pending_seconds: 0,
      scan_runs_past_deadline: 0,
      outbox_failed: 0,
      outbox_dead: 0,
      ...patch.platform,
    },
    generated_at: '2026-10-08T10:00:00Z',
  }
}

describe('buildAttention', () => {
  it('is empty when nothing needs an administrator', () => {
    expect(buildAttention(overview({}), 'super_admin')).toEqual([])
  })

  it('puts critical items first', () => {
    const items = buildAttention(
      overview({
        organizations: { without_owner: 2 },
        platform: { schema_version: 1300 },
        security: { break_glass_sign_ins_7d: 1 },
      }),
      'super_admin'
    )
    expect(items.map((i) => i.id)).toEqual([
      'schema-behind',
      'break-glass-used',
      'orgs-without-owner',
    ])
    expect(items[0].severity).toBe('critical')
  })

  it('a dirty schema wins over a version comparison', () => {
    const items = buildAttention(
      overview({ platform: { schema_dirty: true, schema_version: 1200 } }),
      'readonly'
    )
    expect(items.map((i) => i.id)).toEqual(['schema-dirty'])
  })

  it('does not compare the schema when the shipped version is unknown', () => {
    expect(
      buildAttention(overview({ platform: { schema_shipped: 0, schema_version: 5 } }), 'readonly')
    ).toEqual([])
  })

  it('links one organization without an owner straight to it', () => {
    const [item] = buildAttention(
      overview({
        organizations: { without_owner: 1, without_owner_sample: [{ id: 'org-1', name: 'Acme' }] },
      }),
      'ops_admin'
    )
    expect(item.href).toBe('/admin/organizations/org-1?tab=users')
    expect(item.vars?.name).toBe('Acme')
    expect(item.action).toBe('Add an owner')
  })

  it('offers a read-only administrator a view, not an action', () => {
    const [item] = buildAttention(
      overview({
        organizations: { without_owner: 4, without_owner_sample: [{ id: 'o', name: 'X' }] },
      }),
      'readonly'
    )
    expect(item.href).toBe('/admin/organizations?owner=none')
    expect(item.action).toBe('View')
  })

  it('links the break-glass test only for a super admin (the roster is theirs)', () => {
    const o = overview({ security: { break_glass_tests_overdue: 1 } })
    expect(buildAttention(o, 'super_admin')[0].href).toBe('/admin/security/administrators')
    expect(buildAttention(o, 'ops_admin')[0].href).toBeUndefined()
  })

  it('links refused actions to the filtered activity log', () => {
    const [item] = buildAttention(
      overview({ security: { failed_admin_actions_24h: 3 } }),
      'readonly'
    )
    expect(item.href).toBe('/admin/security/activity?outcome=failure')
  })

  it('reports platform health problems', () => {
    const ids = buildAttention(
      overview({
        platform: {
          platform_sensors: { total: 4, online: 2, offline: 2 },
          scan_runs_past_deadline: 1,
          outbox_dead: 5,
          commands_pending: 3,
          command_oldest_pending_seconds: STALE_COMMAND_SECONDS + 60,
        },
      }),
      'readonly'
    ).map((i) => i.id)
    expect(ids).toEqual([
      'platform-sensors-offline',
      'scan-runs-past-deadline',
      'outbox-dead',
      'commands-waiting',
    ])
  })
})

describe('AttentionQueue', () => {
  it('says all clear when empty', () => {
    render(<AttentionQueue items={[]} />)
    expect(screen.getByText('All clear')).toBeInTheDocument()
  })

  it('renders each item with its action link and filled-in values', () => {
    const items = buildAttention(
      overview({
        organizations: { without_owner: 1, without_owner_sample: [{ id: 'org-1', name: 'Acme' }] },
        platform: { platform_sensors: { total: 3, online: 1, offline: 2 } },
      }),
      'super_admin'
    )
    render(<AttentionQueue items={items} />)
    const list = screen.getByRole('list', { name: 'Needs attention' })
    expect(within(list).getAllByRole('listitem')).toHaveLength(2)
    expect(screen.getByText(/Acme has no owner/)).toBeInTheDocument()
    expect(screen.getByText('2 of 3 platform sensors are offline or stale.')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Add an owner/ })).toHaveAttribute(
      'href',
      '/admin/organizations/org-1?tab=users'
    )
  })
})

describe('visibleAdminNav', () => {
  const urls = (role: AdminIdentity['role']) =>
    visibleAdminNav(role).flatMap((s) => s.items.map((i) => i.url))

  it('hides super-admin pages from other roles', () => {
    expect(urls('readonly')).not.toContain('/admin/security/administrators')
    expect(urls('ops_admin')).not.toContain('/admin/system/admin-sign-in')
    expect(urls('super_admin')).toEqual(
      expect.arrayContaining(['/admin/security/administrators', '/admin/system/admin-sign-in'])
    )
  })

  it('lists every console page exactly once', () => {
    const all = urls('super_admin')
    expect(new Set(all).size).toBe(all.length)
    expect(all).toContain('/admin/security/activity')
    expect(all).not.toContain('/admin/system-logs')
    expect(all).not.toContain('/admin/administrators')
  })
})

describe('AdminCommandMenu', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
    fetchMock.mockReset()
    globalThis.fetch = fetchMock as unknown as typeof fetch
    fetchMock.mockResolvedValue(
      new Response(
        JSON.stringify({
          data: [{ id: 'org-9', name: 'Acme Corp', slug: 'acme' }],
          total: 1,
          page: 1,
          per_page: 8,
          total_pages: 1,
        }),
        { status: 200 }
      )
    )
  })

  async function renderMenu(role: AdminIdentity['role']) {
    mocks.admin.current = { id: 'a', email: 'a@x.test', name: 'A', role }
    const { AdminCommandMenu } = await import('../components/admin-command-menu')
    return render(<AdminCommandMenu />)
  }

  it('lists only the pages the role can open', async () => {
    await renderMenu('readonly')
    expect(screen.getByRole('option', { name: /Admin activity/ })).toBeInTheDocument()
    expect(screen.queryByRole('option', { name: /Administrators/ })).not.toBeInTheDocument()
  })

  it('searches organizations on the server and opens the one picked', async () => {
    const user = userEvent.setup()
    await renderMenu('super_admin')
    await user.type(screen.getByRole('combobox'), 'acme')
    const option = await screen.findByRole('option', { name: /Acme Corp/ })
    const url = String(fetchMock.mock.calls.at(-1)?.[0])
    expect(url).toContain('/api/v1/admin/tenants?')
    expect(url).toContain('search=acme')
    await user.click(option)
    expect(mocks.push).toHaveBeenCalledWith('/admin/organizations/org-9')
  })

  it('does not query organizations for a one-letter search', async () => {
    const user = userEvent.setup()
    await renderMenu('super_admin')
    await user.type(screen.getByRole('combobox'), 'a')
    await new Promise((r) => setTimeout(r, 300))
    await waitFor(() => expect(fetchMock).not.toHaveBeenCalled())
  })
})
