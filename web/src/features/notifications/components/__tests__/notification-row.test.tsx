import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { NotificationRow } from '../notification-row'
import type { UserNotification } from '../../api/use-notification-api'

vi.mock('@/components/link', () => ({
  default: ({ href, children, ...rest }: React.ComponentProps<'a'> & { href: string }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}))

const base: UserNotification = {
  id: 'n1',
  tenant_id: 't1',
  audience: 'user',
  notification_type: 'finding_new',
  title: 'New critical finding',
  severity: 'critical',
  is_read: false,
  created_at: new Date().toISOString(),
}

afterEach(cleanup)

describe('NotificationRow', () => {
  it('navigates on the first click of an unread linked row and marks it read', () => {
    const onMarkAsRead = vi.fn()
    render(
      <NotificationRow
        notification={{ ...base, url: '/findings/123' }}
        onMarkAsRead={onMarkAsRead}
      />
    )
    const link = screen.getByRole('link')
    expect(link.getAttribute('href')).toBe('/findings/123')
    // fireEvent returns false when a handler called preventDefault (no navigation).
    expect(fireEvent.click(link)).toBe(true)
    expect(onMarkAsRead).toHaveBeenCalledWith('n1')
  })

  it('does not mark a read row again', () => {
    const onMarkAsRead = vi.fn()
    render(
      <NotificationRow
        notification={{ ...base, is_read: true, url: '/findings/1' }}
        onMarkAsRead={onMarkAsRead}
      />
    )
    fireEvent.click(screen.getByRole('link'))
    expect(onMarkAsRead).not.toHaveBeenCalled()
  })

  it.each(['https://evil.example/x', '//evil', '/\\evil', 'javascript:alert(1)'])(
    'renders no link for the unsafe target %j',
    (url) => {
      render(<NotificationRow notification={{ ...base, url }} onMarkAsRead={vi.fn()} />)
      expect(screen.queryByRole('link')).toBeNull()
      expect(screen.getByRole('button')).toBeTruthy()
    }
  )

  it('activates a row without a target from the keyboard and names the unread dot', () => {
    const onMarkAsRead = vi.fn()
    const onNavigate = vi.fn()
    render(
      <NotificationRow
        notification={base}
        onMarkAsRead={onMarkAsRead}
        onNavigate={onNavigate}
        compact
      />
    )
    const row = screen.getByRole('button')
    expect(row.getAttribute('tabindex')).toBe('0')
    expect(screen.getByText('Unread', { selector: '.sr-only' })).toBeTruthy()
    fireEvent.keyDown(row, { key: 'Enter' })
    fireEvent.keyDown(row, { key: ' ' })
    expect(onMarkAsRead).toHaveBeenCalledTimes(2)
    expect(onNavigate).toHaveBeenCalledTimes(2)
  })
})
