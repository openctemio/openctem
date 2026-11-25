/**
 * A channel's "View events" opens that channel's events. The ?integration=
 * link is read on every render: after an in-app navigation the first render
 * still sees the previous page's address, so reading it once opened the first
 * channel instead.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, render, screen } from '@testing-library/react'

const FIRST = '0191c2b4-7a1e-7d3a-8f10-2b6a9c4d5e61'
const SECOND = '0191c2b4-7a1e-7d3a-8f10-2b6a9c4d5e62'

const m = vi.hoisted(() => ({ eventsFor: [] as string[] }))

vi.mock('next/navigation', () => ({
  usePathname: () => '/settings/integrations/notifications',
  useRouter: () => ({ push: vi.fn() }),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/features/integrations/api/use-integrations-api', () => ({
  integrationIdFromParam: (v: string | null) => (v && /^[0-9a-f-]{36}$/.test(v) ? v : ''),
  useNotificationIntegrationsApi: () => ({
    data: {
      data: [
        { id: '0191c2b4-7a1e-7d3a-8f10-2b6a9c4d5e61', name: 'First channel', provider: 'slack' },
        { id: '0191c2b4-7a1e-7d3a-8f10-2b6a9c4d5e62', name: 'Second channel', provider: 'email' },
      ],
    },
    isLoading: false,
  }),
  useNotificationEventsApi: (id: string) => {
    m.eventsFor.push(id)
    return { data: { data: [], total: 0 }, error: undefined, isLoading: false, mutate: vi.fn() }
  },
  invalidateNotificationEventsCache: vi.fn(),
}))

import NotificationHistoryPage from '../page'

describe('NotificationHistoryPage', () => {
  afterEach(() => {
    window.history.replaceState(null, '', '/')
    m.eventsFor = []
  })

  it('shows the linked channel when the address catches up after the first render', () => {
    // First render mid-navigation: the address bar still shows the channel list.
    window.history.replaceState(null, '', '/settings/integrations/notifications')
    render(<NotificationHistoryPage />)
    act(() => {
      window.history.replaceState(
        null,
        '',
        `/settings/integrations/notifications/history?integration=${SECOND}`
      )
      window.dispatchEvent(new PopStateEvent('popstate'))
    })
    expect(m.eventsFor.at(-1)).toBe(SECOND)
    expect(screen.getByRole('combobox', { name: 'Channel' }).textContent).toContain(
      'Second channel'
    )
  })

  it('ignores a link value that is not a channel id', () => {
    window.history.replaceState(
      null,
      '',
      '/settings/integrations/notifications/history?integration=..%2Ffindings%3F'
    )
    render(<NotificationHistoryPage />)
    expect(m.eventsFor.at(-1)).toBe(FIRST)
    expect(m.eventsFor.some((id) => id.includes('..'))).toBe(false)
  })

  it('falls back to the first channel without a link', () => {
    render(<NotificationHistoryPage />)
    expect(m.eventsFor.at(-1)).toBe(FIRST)
  })
})
