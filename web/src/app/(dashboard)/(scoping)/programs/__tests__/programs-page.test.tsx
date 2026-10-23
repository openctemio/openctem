import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

import ProgramsPage from '../page'

let granted = new Set<string>()
let state: { data?: unknown[]; error?: unknown; isLoading: boolean } = { isLoading: false }

vi.mock('@/features/programs', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/features/programs')>()),
  usePrograms: () => ({ ...state, mutate: vi.fn() }),
}))
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  useHasPermission: (p: string) => granted.has(p),
}))
vi.mock('@/features/shared/components/gated-section-tabs', () => ({ GatedSectionTabs: () => null }))

describe('programs page', () => {
  beforeEach(() => {
    granted = new Set(['attack_surface:programs:read', 'attack_surface:programs:write'])
    state = { data: [], isLoading: false }
  })

  it('says the user has no access instead of "No programs yet" without programs:read', () => {
    granted = new Set()
    render(<ProgramsPage />)
    expect(screen.getByText(/you do not have access to programs/i)).toBeInTheDocument()
    expect(screen.queryByText('No programs yet')).toBeNull()
  })

  it('shows skeleton rows, not the empty state, while loading', () => {
    state = { isLoading: true }
    const { container } = render(<ProgramsPage />)
    expect(screen.queryByText('No programs yet')).toBeNull()
    expect(
      container.querySelectorAll('[data-slot="skeleton"], .animate-pulse').length
    ).toBeGreaterThan(0)
  })

  it('offers Import program inside the empty state for writers only', () => {
    const { unmount } = render(<ProgramsPage />)
    expect(screen.getAllByRole('link', { name: /import program/i })).toHaveLength(2)
    unmount()
    granted = new Set(['attack_surface:programs:read'])
    render(<ProgramsPage />)
    expect(screen.queryByRole('link', { name: /import program/i })).toBeNull()
  })
})
