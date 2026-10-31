/**
 * Ready to close and Recently auto-closed: rows show the evidence of the
 * scan, confirm and keep-open send one decision for the chosen proposals
 * (keep open with a reason), the actions follow the caller's permissions,
 * and a wrong automatic close reopens in one click.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

import { ReadyToCloseList } from '../components/ready-to-close-list'
import { AutoClosedList } from '../components/auto-closed-list'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn(), warning: vi.fn() }))
vi.mock('sonner', () => ({ toast }))
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}
const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ allowed: new Set<string>() }))
vi.mock('@/lib/permissions', () => ({
  usePermissions: () => ({ can: (p: string) => perms.allowed.has(p) }),
  Permission: { FindingsVerify: 'findings:verify', FindingsStatus: 'findings:status' },
}))

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)
const listProps = {
  page: 1,
  perPage: 20,
  pagination: { pageIndex: 0, pageSize: 20 },
  onPaginationChange: () => {},
}

const proposal = {
  id: 'p1',
  finding_id: 'f1',
  method: 'covered_scan',
  evidence: { tool: 'nuclei', command_id: 'c0ffee00-0000-0000-0000-000000000000', held: true },
  proposed_at: '2026-10-29T10:00:00Z',
  evidence_at: '2026-10-29T10:00:00Z',
  finding_title: 'Exposed admin panel',
  severity: 'critical',
  status: 'confirmed',
  asset_name: 'app.example.com',
  tier: 'critical',
}

beforeEach(() => {
  api.get.mockReset()
  api.post.mockReset()
  toast.success.mockReset()
  perms.allowed = new Set(['findings:verify', 'findings:status'])
})

describe('ReadyToCloseList', () => {
  it('shows the evidence and confirms one proposal', async () => {
    api.get.mockResolvedValue({ data: [proposal], total: 1, page: 1, per_page: 20, total_pages: 1 })
    api.post.mockResolvedValue({ applied: ['p1'], skipped: {}, finding_ids: ['f1'] })
    wrap(<ReadyToCloseList {...listProps} />)
    expect(await screen.findAllByText('Exposed admin panel')).not.toHaveLength(0)
    expect(screen.getAllByText('Held for review').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Critical: a person closes it').length).toBeGreaterThan(0)
    await userEvent.click(screen.getAllByRole('button', { name: 'Confirm close' })[0])
    const dialog = await screen.findByRole('alertdialog')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Confirm close' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/findings/closure/proposals/decide', {
        proposal_ids: ['p1'],
        decision: 'confirm',
      })
    )
  })

  it('keeps a proposal open with the chosen reason', async () => {
    api.get.mockResolvedValue({ data: [proposal], total: 1, page: 1, per_page: 20, total_pages: 1 })
    api.post.mockResolvedValue({ applied: ['p1'], skipped: {}, finding_ids: ['f1'] })
    wrap(<ReadyToCloseList {...listProps} />)
    await userEvent.click((await screen.findAllByRole('button', { name: 'Keep open' }))[0])
    const dialog = await screen.findByRole('alertdialog')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Keep open' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/findings/closure/proposals/decide', {
        proposal_ids: ['p1'],
        decision: 'dismiss',
        reason: 'still_present_manual_check',
        note: undefined,
      })
    )
  })

  it('offers no decision without findings:verify', async () => {
    perms.allowed = new Set()
    api.get.mockResolvedValue({ data: [proposal], total: 1, page: 1, per_page: 20, total_pages: 1 })
    wrap(<ReadyToCloseList {...listProps} />)
    expect(await screen.findAllByText('Exposed admin panel')).not.toHaveLength(0)
    expect(screen.queryByRole('button', { name: 'Confirm close' })).toBeNull()
  })
})

describe('AutoClosedList', () => {
  it('reopens a wrong automatic close', async () => {
    api.get.mockResolvedValue({
      data: [
        {
          finding_id: 'f2',
          finding_title: 'Old TLS',
          severity: 'medium',
          verification: 'covered_scan',
          resolved_at: '2026-10-29T10:00:00Z',
          evidence: { scanner: 'nuclei', scan_id: 'abc' },
        },
      ],
      total: 1,
      page: 1,
      per_page: 20,
      total_pages: 1,
    })
    api.post.mockResolvedValue(undefined)
    wrap(<AutoClosedList {...listProps} />)
    await userEvent.click((await screen.findAllByRole('button', { name: 'Reopen: not fixed' }))[0])
    const dialog = await screen.findByRole('alertdialog')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Reopen: not fixed' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/findings/f2/reopen-not-fixed', {})
    )
  })
})
