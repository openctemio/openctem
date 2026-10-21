import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import NotificationsSettingsPage from '../page'

const update = vi.fn()
let prefs: Record<string, unknown>
vi.mock('@/features/notifications/api/use-notification-api', () => ({
  useNotificationPreferencesApi: () => ({
    data: prefs,
    isLoading: false,
    error: undefined,
    mutate: vi.fn(),
  }),
  updateNotificationPreferences: (...a: unknown[]) => update(...a),
  invalidatePreferencesCache: vi.fn(),
}))
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({ t: (_k: string, fallback?: string) => fallback ?? _k }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

beforeEach(() => {
  update.mockReset()
  update.mockResolvedValue({})
  prefs = {
    in_app_enabled: true,
    email_digest: 'none',
    muted_types: [],
    min_severity: 'info',
    auto_watch: true,
    updated_at: '2026-10-20T00:00:00Z',
  }
})

describe('notification preferences: watching', () => {
  it('shows the auto-watch switch on by default', () => {
    render(<NotificationsSettingsPage />)
    expect(screen.getByRole('switch', { name: 'Watch what I take part in' })).toBeChecked()
  })

  it('saves the switch', async () => {
    render(<NotificationsSettingsPage />)
    await userEvent.click(screen.getByRole('switch', { name: 'Watch what I take part in' }))
    await userEvent.click(screen.getByRole('button', { name: /save changes/i }))
    expect(update).toHaveBeenCalledWith(expect.objectContaining({ auto_watch: false }))
  })

  it('treats a missing value as on', () => {
    delete prefs.auto_watch
    render(<NotificationsSettingsPage />)
    expect(screen.getByRole('switch', { name: 'Watch what I take part in' })).toBeChecked()
  })
})
