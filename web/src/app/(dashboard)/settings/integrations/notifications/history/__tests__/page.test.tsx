/**
 * A channel's "View events" opens that channel's events. The ?integration=
 * link is read on every render: after an in-app navigation the first render
 * still sees the previous page's address, so reading it once opened the first
 * channel instead.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, render, screen } from '@testing-library/react'

const m = vi.hoisted(() => ({ eventsFor: [] as string[] }))

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/features/integrations/api/use-integrations-api', () => ({
  useNotificationIntegrationsApi: () => ({
    data: {
      data: [
        { id: 'first', name: 'First channel', provider: 'slack' },
        { id: 'second', name: 'Second channel', provider: 'email' },
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
        '/settings/integrations/notifications/history?integration=second'
      )
      window.dispatchEvent(new PopStateEvent('popstate'))
    })
    expect(m.eventsFor.at(-1)).toBe('second')
    expect(screen.getByRole('combobox', { name: 'Channel' }).textContent).toContain(
      'Second channel'
    )
  })

  it('falls back to the first channel without a link', () => {
    render(<NotificationHistoryPage />)
    expect(m.eventsFor.at(-1)).toBe('first')
  })
})
