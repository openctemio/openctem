import axe from 'axe-core'
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'

let pathname = '/findings'
vi.mock('next/navigation', () => ({
  usePathname: () => pathname,
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), prefetch: vi.fn() }),
}))
vi.mock('next/link', () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
  useLinkStatus: () => ({ pending: false }),
}))

const fetched: boolean[] = []
const state: { views: Array<{ key: string; count: number; params: string }> } = { views: [] }
vi.mock('@/features/findings/api/use-quick-views', () => ({
  useFindingQuickViews: (enabled: boolean) => {
    fetched.push(enabled)
    return { data: enabled ? { views: state.views } : undefined }
  },
}))
vi.mock('@/components/ui/sidebar', () => ({
  SidebarMenuSub: ({ children, ...p }: { children: React.ReactNode }) => <ul {...p}>{children}</ul>,
  SidebarMenuSubItem: ({ children }: { children: React.ReactNode }) => <li>{children}</li>,
  SidebarMenuSubButton: ({
    children,
    isActive,
  }: {
    children: React.ReactNode
    isActive?: boolean
  }) => <div data-active={isActive}>{children}</div>,
  useSidebarActions: () => ({ setOpenMobile: vi.fn() }),
  SidebarMenuAction: (p: React.ComponentProps<'button'>) => <button type="button" {...p} />,
}))
vi.mock('@/features/nav-pins/api/use-nav-pins', () => ({
  useNavPins: () => ({ isPinned: () => false, toggle: vi.fn() }),
}))

import { FindingsQuickViews } from '../findings-quick-views'

const ALL = [
  { key: 'active', count: 12, params: 'state=open' },
  { key: 'needs_triage', count: 0, params: 'status=new' },
  { key: 'my_queue', count: 4, params: 'state=open&related_to=me' },
  { key: 'sla_breached', count: 1, params: 'state=open&sla_status=overdue,exceeded' },
  { key: 'pending_approval', count: 2, params: 'pending_approval=true' },
  { key: 'accepted_expiring', count: 1, params: 'status=accepted&acceptance_expires_at_lte=P30D' },
  { key: 'closed', count: 40, params: 'state=closed' },
]

beforeEach(() => {
  pathname = '/findings'
  state.views = ALL
  fetched.length = 0
  window.history.replaceState(null, '', '/findings')
})

describe('FindingsQuickViews', () => {
  it('lists the seven views as links with the API params', () => {
    render(<FindingsQuickViews />)
    const list = screen.getByRole('list', { name: 'Findings views' })
    const links = within(list).getAllByRole('link')
    expect(links).toHaveLength(7)
    expect(within(list).getByRole('link', { name: /^Active/ })).toHaveAttribute(
      'href',
      '/findings?state=open'
    )
    expect(within(list).getByRole('link', { name: /^Needs triage/ })).toHaveAttribute(
      'href',
      '/findings?status=new&state=all'
    )
  })

  it('shows counts, and nothing for a zero', () => {
    render(<FindingsQuickViews />)
    expect(screen.getByRole('link', { name: /^Active/ })).toHaveTextContent('12')
    expect(screen.getByRole('link', { name: /^Needs triage/ })).not.toHaveTextContent(/\d/)
    expect(screen.getByRole('link', { name: /^Closed/ })).toHaveTextContent('40')
  })

  it('puts a breached SLA count in the error colour, and no other count', () => {
    render(<FindingsQuickViews />)
    const sla = within(screen.getByRole('link', { name: /^SLA breached/ })).getByText('1')
    expect(sla.className).toContain('text-destructive')
    const mine = within(screen.getByRole('link', { name: /^My queue/ })).getByText('4')
    expect(mine.className).not.toContain('text-destructive')
  })

  it('marks the view the URL is', () => {
    window.history.replaceState(null, '', '/findings?state=closed')
    render(<FindingsQuickViews />)
    expect(screen.getByRole('link', { name: /^Closed/ })).toHaveAttribute('aria-current', 'page')
    expect(screen.getByRole('link', { name: /^Active/ })).not.toHaveAttribute('aria-current')
  })

  it('renders nothing, and asks for no counts, off the findings list', () => {
    pathname = '/assets'
    const { container } = render(<FindingsQuickViews />)
    expect(container).toBeEmptyDOMElement()
    expect(fetched.every((enabled) => enabled === false)).toBe(true)
  })

  it('renders nothing until the counts arrive', () => {
    state.views = []
    const { container } = render(<FindingsQuickViews />)
    expect(container).toBeEmptyDOMElement()
  })

  it('has no accessibility violations', async () => {
    const { container } = render(<FindingsQuickViews />)
    const res = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false }, region: { enabled: false } },
    })
    expect(res.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' '))}`)).toEqual(
      []
    )
  })
})
