import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { LayoutDashboard } from 'lucide-react'

const put = vi.fn()
const mutate = vi.fn()
let data: unknown = undefined
vi.mock('@/lib/api/client', () => ({ get: vi.fn(), put: (...a: unknown[]) => put(...a) }))
vi.mock('swr', () => ({ default: () => ({ data, mutate }) }))
vi.mock('@/context/tenant-provider', () => ({ useCurrentTenantId: () => 't1' }))
vi.mock('sonner', () => ({ toast: { error: vi.fn() } }))
vi.mock('next/navigation', () => ({ usePathname: () => '/my-work' }))
vi.mock('@/components/ui/sidebar', async (orig) => ({
  ...(await orig<typeof import('@/components/ui/sidebar')>()),
  useSidebarActions: () => ({ setOpenMobile: vi.fn() }),
}))

import { togglePin } from '../api/use-nav-pins'
import { NavPinned, pinnedRows } from '@/components/layout/nav-pinned'
import { PinAction } from '../components/pin-action'
import { SidebarProvider } from '@/components/ui/sidebar'

const pages = new Map([
  ['/my-work', { title: 'My work', icon: LayoutDashboard }],
  ['/', { title: 'Overview' }],
])

describe('togglePin', () => {
  it('adds at the end, removes, and refuses past the maximum', () => {
    const a = { kind: 'page' as const, ref: '/' }
    const b = { kind: 'page' as const, ref: '/my-work' }
    expect(togglePin([a], b, 12)).toEqual([a, b])
    expect(togglePin([a, b], a, 12)).toEqual([b])
    expect(togglePin([a], b, 1)).toBeNull()
  })
})

describe('pinnedRows', () => {
  it('builds links for each kind and leaves out what the sidebar does not offer', () => {
    const rows = pinnedRows(
      [
        { kind: 'page', ref: '/my-work' },
        { kind: 'page', ref: '/admin-only' },
        { kind: 'quick_view', ref: 'needs_triage', params: 'status=new', count: 12 },
        {
          kind: 'saved_view',
          ref: '00000000-0000-0000-0000-000000000001',
          name: 'Edge triage',
          count: 3,
        },
        { kind: 'saved_view', ref: '00000000-0000-0000-0000-000000000002' },
      ],
      pages,
      false,
      () => 'Needs triage'
    )
    expect(rows.map((r) => [r.label, r.href, r.count])).toEqual([
      ['My work', '/my-work', undefined],
      ['Needs triage', expect.stringMatching(/^\/findings\?.*status=new/), 12],
      ['Edge triage', '/findings?view=00000000-0000-0000-0000-000000000001', 3],
    ])
  })
})

describe('NavPinned', () => {
  it('shows nothing until something is pinned', () => {
    data = { data: [], max: 12, include_informational: false }
    const { container } = render(
      <SidebarProvider>
        <NavPinned groups={[]} />
      </SidebarProvider>
    )
    expect(container.querySelector('[data-slot="nav-pinned-item"]')).toBeNull()
  })

  it('lists the pins with their counts and an unpin button', () => {
    data = {
      data: [
        { kind: 'page', ref: '/my-work' },
        {
          kind: 'saved_view',
          ref: '00000000-0000-0000-0000-000000000001',
          name: 'Edge triage',
          count: 31,
        },
      ],
      max: 12,
      include_informational: false,
    }
    render(
      <SidebarProvider>
        <NavPinned groups={[{ title: '', items: [{ title: 'My work', url: '/my-work' }] }]} />
      </SidebarProvider>
    )
    expect(screen.getByRole('link', { name: /My work/ }).getAttribute('aria-current')).toBe('page')
    expect(screen.getByRole('link', { name: /Edge triage/ }).textContent).toContain('31')
    expect(screen.getByRole('button', { name: 'Unpin Edge triage' })).toBeTruthy()
  })
})

describe('PinAction', () => {
  it('writes the new list through the API', async () => {
    data = { data: [{ kind: 'page', ref: '/' }], max: 12, include_informational: false }
    put.mockResolvedValue({ data: [], max: 12, include_informational: false })
    render(
      <SidebarProvider>
        <ul>
          <li>
            <PinAction pin={{ kind: 'page', ref: '/my-work' }} label="My work" />
          </li>
        </ul>
      </SidebarProvider>
    )
    fireEvent.click(screen.getByRole('button', { name: 'Pin My work to the top' }))
    await vi.waitFor(() =>
      expect(put).toHaveBeenCalledWith('/api/v1/me/pins', {
        pins: [
          { kind: 'page', ref: '/' },
          { kind: 'page', ref: '/my-work' },
        ],
      })
    )
  })
})
