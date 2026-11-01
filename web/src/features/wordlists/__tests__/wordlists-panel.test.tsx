import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SWRConfig } from 'swr'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/lib/api/client', () => ({
  fetcher: () => Promise.resolve({ items: [], limit: 10 }),
  fetcherWithOptions: vi.fn(),
}))
vi.mock('@/lib/permissions', () => ({
  Permission: { ContentPacksRead: 'content:read', ContentPacksWrite: 'content:write' },
  usePermissions: () => ({ can: () => true }),
}))
vi.mock('../api/use-wordlists', () => ({
  useWordlists: () => ({ data: { items: [], limit: 10 }, error: null, isLoading: false }),
  useWordlistPreview: () => ({ data: null, error: null, isLoading: false }),
  invalidateWordlists: vi.fn(),
  updateWordlist: vi.fn(),
  deleteWordlist: vi.fn(),
  createWordlist: vi.fn(),
}))

import { WordlistsPanel } from '../components/wordlists-panel'

describe('WordlistsPanel', () => {
  it('shows the empty list inside the one card, not a card inside a card', () => {
    const { container } = render(
      <SWRConfig value={{ provider: () => new Map() }}>
        <WordlistsPanel />
      </SWRConfig>
    )
    expect(screen.getByText('No lists yet')).toBeInTheDocument()
    expect(container.querySelector('[data-slot=card] [data-slot=card]')).toBeNull()
  })
})
