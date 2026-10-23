import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { NotificationBell } from '../notification-bell'

const mutate = vi.fn()
const state = {
  list: { data: undefined as unknown, isLoading: false, error: undefined as unknown, mutate },
  unread: { data: { count: 3 } as unknown, mutate: vi.fn() },
}

vi.mock('@/features/notifications/api/use-notification-api', () => ({
  useNotificationsApi: () => state.list,
  useUnreadCountApi: () => state.unread,
}))
vi.mock('@/features/notifications/api/use-mark-notifications', () => ({
  useMarkNotifications: () => ({ markRead: vi.fn(), markAllRead: vi.fn() }),
}))
vi.mock('@/hooks/use-websocket', () => ({ useUserNotificationChannel: vi.fn() }))
vi.mock('@/hooks/use-display-user', () => ({ useDisplayUser: () => ({ id: 'u1' }) }))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
vi.mock('@/components/link', () => ({
  default: ({ href, children, ...rest }: React.ComponentProps<'a'> & { href: string }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}))

function openBell() {
  render(<NotificationBell />)
  const trigger = screen.getAllByRole('button')[0]
  fireEvent.pointerDown(trigger, { button: 0, ctrlKey: false })
  fireEvent.click(trigger)
}

beforeEach(() => {
  mutate.mockReset()
  state.list = { data: undefined, isLoading: false, error: undefined, mutate }
  state.unread = { data: { count: 3 }, mutate: vi.fn() }
})
afterEach(cleanup)

describe('NotificationBell', () => {
  it('puts the unread count in the trigger name', () => {
    render(<NotificationBell />)
    expect(screen.getByRole('button', { name: 'Notifications, 3 unread' })).toBeTruthy()
  })

  it('uses a plain name when nothing is unread', () => {
    state.unread = { data: { count: 0 }, mutate: vi.fn() }
    render(<NotificationBell />)
    expect(screen.getByRole('button', { name: 'Notifications' })).toBeTruthy()
  })

  it('shows an error with retry instead of "all caught up" when the fetch fails', () => {
    state.list = { data: undefined, isLoading: false, error: new Error('boom'), mutate }
    openBell()
    expect(screen.getByRole('alert')).toBeTruthy()
    expect(screen.queryByText('You are all caught up')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(mutate).toHaveBeenCalled()
  })

  it('renders a row without a target as a keyboard-reachable button', () => {
    state.list = {
      data: {
        data: [
          {
            id: 'n1',
            tenant_id: 't1',
            audience: 'user',
            notification_type: 'system_alert',
            title: 'Disk almost full',
            severity: 'high',
            is_read: false,
            created_at: new Date().toISOString(),
          },
        ],
      },
      isLoading: false,
      error: undefined,
      mutate,
    }
    openBell()
    const row = screen.getByRole('button', { name: /Disk almost full/ })
    expect(row.getAttribute('tabindex')).toBe('0')
  })
})
