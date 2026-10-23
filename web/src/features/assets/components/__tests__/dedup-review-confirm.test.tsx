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
  AssetAttentionTabs: () => null,
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
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

describe('Duplicate review', () => {
  it('merging deletes the duplicates, so it asks first and names them', async () => {
    render(<DedupReviewPage />)
    await userEvent.click(screen.getByRole('button', { name: 'Merge' }))
    expect(approveDedupReview).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Merge 2 assets into web-01?')
    expect(dialog).toHaveTextContent('WEB-01, web-01.local')
    await userEvent.click(within(dialog).getByRole('button', { name: 'Merge' }))
    await waitFor(() => expect(approveDedupReview).toHaveBeenCalledWith('r1'))
  })

  it('keeping them separate changes no asset and needs no confirmation', async () => {
    render(<DedupReviewPage />)
    await userEvent.click(screen.getByRole('button', { name: 'Keep separate' }))
    await waitFor(() => expect(rejectDedupReview).toHaveBeenCalledWith('r1'))
    expect(screen.queryByRole('alertdialog')).toBeNull()
  })
})
