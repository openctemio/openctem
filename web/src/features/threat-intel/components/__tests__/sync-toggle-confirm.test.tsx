/** Turning a feed on starts scheduled downloads: it asks first. Turning it off is one click. */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const setSyncEnabled = vi.hoisted(() => vi.fn())
vi.mock('../../hooks/use-threat-intel', () => ({
  triggerSync: vi.fn(),
  setSyncEnabled,
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

import { SyncStatusManager } from '../sync-status-manager'
import type { SyncStatus } from '@/lib/api/threatintel-types'

const status = (enabled: boolean) =>
  ({
    source: 'kev',
    enabled,
    last_sync_status: 'never',
    last_sync_at: null,
    last_error: '',
    records_synced: 0,
  }) as unknown as SyncStatus

beforeEach(() => {
  setSyncEnabled.mockReset()
  setSyncEnabled.mockResolvedValue(undefined)
})

describe('feed sync switch', () => {
  it('asks before turning a feed on', async () => {
    render(<SyncStatusManager statuses={[status(false)]} />)
    await userEvent.click(screen.getByRole('switch'))
    expect(setSyncEnabled).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Turn on CISA KEV sync?')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Turn on sync' }))
    await waitFor(() => expect(setSyncEnabled).toHaveBeenCalledWith('kev', true))
  })

  it('turns a feed off in one click', async () => {
    render(<SyncStatusManager statuses={[status(true)]} />)
    await userEvent.click(screen.getByRole('switch'))
    await waitFor(() => expect(setSyncEnabled).toHaveBeenCalledWith('kev', false))
    expect(screen.queryByRole('alertdialog')).toBeNull()
  })
})
