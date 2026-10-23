/**
 * research/245 area B, /attack-surface/review: "Hide items" closes the list
 * even when a deep link (?tab=, ?reason=) opened it.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

vi.mock('@/features/attack-surface', () => ({
  AttackSurfaceSectionTabs: () => null,
  EASMDecidePanel: () => null,
  EASMReviewQueue: () => <div data-testid="queue" />,
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))

const { default: Page } = await import('@/app/(dashboard)/(scoping)/attack-surface/review/page')

beforeEach(() => window.history.replaceState(null, '', '/attack-surface/review'))

describe('attack surface review page', () => {
  it.each(['?tab=rejected', '?reason=fqdn_under_asserted_root', '?all=1'])(
    'Hide items closes the list opened by %s',
    async (qs) => {
      window.history.replaceState(null, '', `/attack-surface/review${qs}`)
      render(<Page />)
      expect(screen.getByTestId('queue')).toBeInTheDocument()
      await userEvent.click(screen.getByRole('button', { name: 'Hide items' }))
      expect(window.location.search).toBe('')
      expect(screen.queryByTestId('queue')).toBeNull()
      expect(screen.getByRole('button', { name: 'Show all items' })).toBeInTheDocument()
    }
  )
})
