import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

// The API answers 403 to scan, approve, dismiss and type changes without
// assets:write; the page must not offer them to a reader.

const perms = vi.hoisted(() => ({ write: true, approveAll: vi.fn(), approveBatch: vi.fn() }))
vi.mock('@/lib/permissions', () => ({
  Permission: { AssetsWrite: 'assets:write' },
  usePermissions: () => ({ can: (p: string) => p === 'assets:write' && perms.write }),
}))

const trigger = { trigger: vi.fn(), isMutating: false }
vi.mock('@/features/relationships/api/use-relationship-suggestions', () => ({
  useRelationshipSuggestions: () => ({
    data: {
      data: [
        {
          id: 's1',
          source_asset_id: 'a1',
          source_asset_name: 'api.example.com',
          source_asset_type: 'domain',
          target_asset_id: 'a2',
          target_asset_name: '192.0.2.10',
          target_asset_type: 'ip_address',
          relationship_type: 'resolves_to',
          reason: 'DNS A record',
          confidence: 0.9,
        },
      ],
      total: 1,
    },
    error: undefined,
    isLoading: false,
    isValidating: false,
  }),
  useApproveSuggestion: () => trigger,
  useDismissSuggestion: () => trigger,
  useApproveAllSuggestions: () => ({ trigger: perms.approveAll, isMutating: false }),
  useGenerateSuggestions: () => trigger,
  useUpdateSuggestionType: () => trigger,
  useApproveBatchSuggestions: () => ({ trigger: perms.approveBatch, isMutating: false }),
}))
vi.mock('@/features/assets/components/assets-section-tabs', () => ({
  AssetsSectionTabs: () => null,
}))
vi.mock('@/features/assets/components/attention/attention-queue-header', () => ({
  AttentionQueueHeader: () => null,
}))
vi.mock('@/hooks/use-url-param', () => ({ useUrlFilter: () => ['', vi.fn()] }))
vi.mock('@/hooks/use-list-params', () => ({
  useListParams: () => ({ page: 1, setPage: vi.fn(), perPage: 20, setPagination: vi.fn() }),
}))

import RelationshipSuggestionsPage from '../page'

describe('Relationship suggestions: approving asks first', () => {
  beforeEach(() => {
    perms.write = true
    perms.approveAll.mockReset().mockResolvedValue(undefined)
    perms.approveBatch.mockReset().mockResolvedValue({ count: 1 })
  })

  it('Approve all names the count and does not create anything before the confirmation', async () => {
    render(<RelationshipSuggestionsPage />)
    await userEvent.click(screen.getByRole('button', { name: /approve all/i }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Approve all 1 suggestions?')
    // Relationships can be removed afterwards, so it must not claim otherwise.
    expect(dialog).not.toHaveTextContent(/cannot be undone/i)
    expect(perms.approveAll).not.toHaveBeenCalled()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Approve 1 suggestions' }))
    await waitFor(() => expect(perms.approveAll).toHaveBeenCalled())
  })

  it('approving the selection lists what it links and counts it in the button', async () => {
    render(<RelationshipSuggestionsPage />)
    await userEvent.click(screen.getAllByRole('checkbox')[0])
    await userEvent.click(
      within(await screen.findByRole('toolbar')).getByRole('button', { name: 'Approve' })
    )
    const dialog = await screen.findByRole('alertdialog')
    expect(within(dialog).getByText('api.example.com → 192.0.2.10')).toBeInTheDocument()
    expect(perms.approveBatch).not.toHaveBeenCalled()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Approve 1 suggestions' }))
    await waitFor(() => expect(perms.approveBatch).toHaveBeenCalledWith(['s1']))
  })
})
