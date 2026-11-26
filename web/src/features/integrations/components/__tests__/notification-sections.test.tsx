import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

const can = { manage: false }
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useHasPermission: (p: string) => (p === 'integrations:manage' ? can.manage : true),
}))
vi.mock('next/navigation', () => ({
  usePathname: () => '/settings/integrations/notifications',
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), prefetch: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}))

import { NotificationSectionHeader } from '../notification-sections'

describe('NotificationSectionHeader', () => {
  beforeEach(() => {
    can.manage = false
  })

  it('shows no Events or Queue link to a reader without integrations:manage', () => {
    render(<NotificationSectionHeader />)
    expect(screen.queryByRole('link', { name: /Events/ })).toBeNull()
    expect(screen.queryByRole('link', { name: /Queue/ })).toBeNull()
    expect(screen.getByRole('heading', { name: 'Notification channels' })).toBeInTheDocument()
  })

  it('shows Channels, Events and Queue to a channel manager', () => {
    can.manage = true
    render(<NotificationSectionHeader />)
    expect(screen.getByRole('link', { name: /Channels/ })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Events/ })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Queue/ })).toBeInTheDocument()
  })
})
