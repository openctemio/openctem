import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

// The API answers 403 to scan, approve, dismiss and type changes without
// assets:write; the page must not offer them to a reader.

const perms = vi.hoisted(() => ({ write: false }))
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
  useApproveAllSuggestions: () => trigger,
  useGenerateSuggestions: () => trigger,
  useUpdateSuggestionType: () => trigger,
  useApproveBatchSuggestions: () => trigger,
}))
vi.mock('@/features/assets/components/assets-section-tabs', () => ({
  AssetsSectionTabs: () => null,
}))
vi.mock('@/hooks/use-url-param', () => ({ useUrlFilter: () => ['', vi.fn()] }))
vi.mock('@/hooks/use-list-params', () => ({
  useListParams: () => ({ page: 1, setPage: vi.fn(), perPage: 20, setPagination: vi.fn() }),
}))

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
    expect(screen.queryByRole('button', { name: /dismiss suggestion/i })).toBeNull()
    expect(screen.queryByTitle('Change relationship type')).toBeNull()
    expect(screen.queryByRole('checkbox')).toBeNull()
  })

  it('offers the review actions to a holder of assets:write', () => {
    perms.write = true
    render(<RelationshipSuggestionsPage />)
    expect(screen.getByRole('button', { name: /scan/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /approve all/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^approve$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /dismiss suggestion/i })).toBeInTheDocument()
    expect(screen.getByTitle('Change relationship type')).toBeInTheDocument()
  })
})
