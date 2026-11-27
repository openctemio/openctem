import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

// The API answers 403 to scan, approve, dismiss and type changes without
// assets:write; the page must not offer them to a reader.

const perms = vi.hoisted(() => ({ write: false }))
vi.mock('@/lib/permissions', () => ({
  Permission: { AssetsWrite: 'assets:write' },
  usePermissions: () => ({ can: (p: string) => p === 'assets:write' && perms.write }),
}))

const trigger = { trigger: vi.fn(() => Promise.resolve()), isMutating: false }
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
  useApproveAllSuggestions: () => trigger,
  useGenerateSuggestions: () => trigger,
  useUpdateSuggestionType: () => trigger,
  useApproveBatchSuggestions: () => trigger,
}))
vi.mock('@/features/assets/components/assets-section-tabs', () => ({
  AssetsSectionTabs: () => null,
}))
vi.mock('@/features/assets/components/attention/attention-queue-header', () => ({
  AttentionQueueHeader: () => null,
}))
vi.mock('@/hooks/use-list-params', () => ({
  useListParams: () => ({
    page: 1,
    perPage: 25,
    q: '',
    searchTerm: '',
    pagination: { pageIndex: 0, pageSize: 25 },
    setPage: vi.fn(),
    setPagination: vi.fn(),
    setSearch: vi.fn(),
  }),
}))
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => false }))

import RelationshipSuggestionsPage from '../page'

describe('Relationship suggestions: actions follow assets:write', () => {
  beforeEach(() => {
    perms.write = false
  })

  it('shows a reader the queue without Scan, Approve, Dismiss or type editing', () => {
    render(<RelationshipSuggestionsPage />)
    expect(screen.getByText('api.example.com')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /scan/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /approve/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /reject|dismiss/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /^actions for/i })).toBeNull()
    expect(screen.queryByRole('checkbox')).toBeNull()
  })

  it('offers the review actions to a holder of assets:write, in the row', async () => {
    perms.write = true
    render(<RelationshipSuggestionsPage />)
    expect(screen.getByRole('button', { name: /scan/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /approve all/i })).toBeInTheDocument()
    // The two decisions are buttons in the row, named after the suggestion.
    const approve = document.querySelector('[data-slot="queue-approve"]')
    const dismiss = document.querySelector('[data-slot="queue-reject"]')
    expect(approve).toHaveTextContent('Approve')
    expect(dismiss).toHaveTextContent('Dismiss')
    // The type change is in the row's More.
    await userEvent.click(
      screen.getByRole('button', { name: 'Actions for api.example.com to 192.0.2.10' })
    )
    expect(await screen.findByText('Change relationship type')).toBeInTheDocument()
  })

  it('dismissing calls the API at once and says so', async () => {
    perms.write = true
    render(<RelationshipSuggestionsPage />)
    await userEvent.click(document.querySelector<HTMLElement>('[data-slot="queue-reject"]')!)
    await waitFor(() => expect(trigger.trigger).toHaveBeenCalledWith('s1'))
    await waitFor(() =>
      expect(document.querySelector('[data-slot="queue-announcer"]')).toHaveTextContent(
        'Suggestion dismissed'
      )
    )
  })

  it('shows the link and its reason in one column on a wide screen', () => {
    render(<RelationshipSuggestionsPage />)
    expect(screen.getByRole('columnheader', { name: 'Suggested link' })).toBeInTheDocument()
    const cell = screen.getByText('DNS A record').closest('td') as HTMLElement
    expect(cell).toHaveTextContent('api.example.com')
    expect(cell).toHaveTextContent('Resolves to')
    expect(cell).toHaveTextContent('192.0.2.10')
    // The type of each asset is in its name's tooltip.
    expect(screen.getByTitle('api.example.com (Domain)')).toBeInTheDocument()
  })
})
