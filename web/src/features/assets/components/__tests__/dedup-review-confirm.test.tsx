import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { approveDedupReview, rejectDedupReview } from '../../api/use-asset-dedup'
import { DedupReviewPage } from '../dedup-review-page'

vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('../assets-section-tabs', () => ({
  AssetsSectionTabs: () => null,
}))
vi.mock('../attention/attention-queue-header', () => ({ AttentionQueueHeader: () => null }))
const perm = vi.hoisted(() => ({ canDelete: true }))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: () => perm.canDelete }),
  useHasPermission: () => perm.canDelete,
  Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1' }, isLoading: false }),
}))
vi.mock('../../api/use-asset-dedup', () => ({
  useDedupReviews: () => ({
    data: {
      data: [
        {
          id: 'r1',
          tenant_id: 't1',
          normalized_name: 'web-01.acme.example',
          asset_type: 'host',
          keep_asset_id: 'a1',
          keep_asset_name: 'web-01',
          keep_finding_count: 3,
          merge_asset_ids: ['a2', 'a3'],
          merge_asset_names: ['WEB-01', 'web-01.local'],
          merge_finding_count: 2,
          status: 'pending',
          reason: 'shared_ip',
          created_at: '2026-10-01T00:00:00Z',
        },
      ],
      total: 1,
    },
    isLoading: false,
    error: undefined,
    mutate: vi.fn(),
  }),
  approveDedupReview: vi.fn(() => Promise.resolve()),
  rejectDedupReview: vi.fn(() => Promise.resolve()),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

/** The two decisions are buttons in the row (the queue add-on), not a menu. */
function decision(which: 'merge' | 'keep') {
  const slot = which === 'merge' ? 'queue-approve' : 'queue-reject'
  const button = document.querySelector<HTMLButtonElement>(`[data-slot="${slot}"]`)
  if (!button) throw new Error(`no ${which} button`)
  return button
}

describe('Duplicate review', () => {
  it('shows a review on one line: identity and type, reason, what stays and what merges', () => {
    render(<DedupReviewPage />)
    expect(screen.getByText('web-01.acme.example')).toBeInTheDocument()
    expect(screen.getByText('WEB-01, web-01.local')).toBeInTheDocument()
    expect(screen.getByText('2 assets, 2 findings')).toBeInTheDocument()
    expect(screen.getByText('3 findings')).toBeInTheDocument()
  })

  it('merging deletes the duplicates, so it asks first and names them', async () => {
    render(<DedupReviewPage />)
    expect(decision('merge')).toHaveTextContent('Merge')
    await userEvent.click(decision('merge'))
    expect(approveDedupReview).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Merge 2 assets into web-01?')
    expect(dialog).toHaveTextContent('WEB-01, web-01.local')
    const confirm = within(dialog).getByRole('button', { name: 'Merge 2 assets' })
    // The count of assets that go away is typed before the merge runs.
    expect(confirm).toBeDisabled()
    await userEvent.type(within(dialog).getByRole('textbox'), '2')
    await userEvent.click(confirm)
    await waitFor(() => expect(approveDedupReview).toHaveBeenCalledWith('r1'))
  })

  it('keeping them separate changes no asset and needs no confirmation', async () => {
    render(<DedupReviewPage />)
    expect(decision('keep')).toHaveTextContent('Keep separate')
    await userEvent.click(decision('keep'))
    await waitFor(() => expect(rejectDedupReview).toHaveBeenCalledWith('r1'))
    expect(screen.queryByRole('alertdialog')).toBeNull()
  })

  it('says the outcome to assistive technology as well as in a toast', async () => {
    render(<DedupReviewPage />)
    await userEvent.click(decision('keep'))
    await waitFor(() =>
      expect(document.querySelector('[data-slot="queue-announcer"]')).toHaveTextContent(
        'Kept as separate assets'
      )
    )
  })

  it('has no row menu: the decisions need no menu to open first', () => {
    render(<DedupReviewPage />)
    expect(screen.queryByRole('button', { name: 'Actions for web-01.acme.example' })).toBeNull()
  })

  it('a user who may not delete assets sees the reviews without decisions', () => {
    perm.canDelete = false
    try {
      render(<DedupReviewPage />)
      expect(screen.getByText('web-01.acme.example')).toBeInTheDocument()
      expect(document.querySelector('[data-slot="queue-approve"]')).toBeNull()
      expect(document.querySelector('[data-slot="queue-reject"]')).toBeNull()
    } finally {
      perm.canDelete = true
    }
  })
})
