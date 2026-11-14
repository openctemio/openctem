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

describe('failed feed', () => {
  it('shows when the last import succeeded', () => {
    const failed = {
      ...status(true),
      last_sync_status: 'failed',
      last_sync_at: new Date().toISOString(),
      last_success_at: new Date(Date.now() - 3 * 24 * 3600 * 1000).toISOString(),
      last_error: 'expired',
    } as unknown as SyncStatus
    render(<SyncStatusManager statuses={[failed]} />)
    expect(screen.getByText(/Last successful import:/)).toBeTruthy()
  })

  it('says so when no import ever succeeded', () => {
    const failed = { ...status(true), last_sync_status: 'failed' } as unknown as SyncStatus
    render(<SyncStatusManager statuses={[failed]} />)
    expect(screen.getByText('No import has succeeded yet')).toBeTruthy()
  })
})

describe('a feed the console has no entry for', () => {
  // Owner report 2026-11-14: the API listed a third feed ("vulnfeed") and the
  // Sync status tab threw "reading 'icon'" into the route's error boundary.
  const feed = (source: string) =>
    ({
      ...status(true),
      source,
      last_sync_status: 'failed',
      last_error: 'bundle expired',
    }) as unknown as SyncStatus

  it('shows a known extra feed under its own name', () => {
    render(<SyncStatusManager statuses={[status(true), feed('vulnfeed')]} />)
    expect(screen.getByText('Vulnerability feed')).toBeInTheDocument()
    expect(screen.getByText('CISA KEV')).toBeInTheDocument()
  })

  it('shows an unknown feed under its id with a generic description, without throwing', () => {
    render(<SyncStatusManager statuses={[feed('future-feed')]} />)
    expect(screen.getByText('future-feed')).toBeInTheDocument()
    expect(screen.getByText('Threat intelligence feed')).toBeInTheDocument()
  })
})
