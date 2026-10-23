import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

const state = vi.hoisted(() => ({ current: {} as Record<string, unknown> }))
vi.mock('@/features/attack-surface', () => ({
  useExposureChains: () => state.current,
  PathGraph: () => null,
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))

const { default: ExposureChainsPage } = await import('../page')

describe('exposure chains page layout', () => {
  it('keeps the page gap above a load error', () => {
    state.current = {
      chains: undefined,
      error: new Error('boom'),
      isLoading: false,
      mutate: vi.fn(),
    }
    render(<ExposureChainsPage />)
    const alert = screen.getByRole('alert')
    expect(alert.parentElement).toHaveClass('mt-5')
  })

  it('keeps the page gap above the no-relationships state', () => {
    state.current = {
      chains: { summary: { hasRelationshipData: false }, chains: [] },
      error: undefined,
      isLoading: false,
      mutate: vi.fn(),
    }
    const { container } = render(<ExposureChainsPage />)
    expect(screen.getByText('No relationship data yet').closest('.mt-5')).not.toBeNull()
    expect(container.textContent).not.toContain(' — ')
  })

  it('explains chains without dash asides', () => {
    state.current = {
      chains: {
        summary: { hasRelationshipData: true, entryPoints: 1, targetsAtRisk: 0, totalChains: 0 },
        chains: [],
      },
      error: undefined,
      isLoading: false,
      mutate: vi.fn(),
    }
    const { container } = render(<ExposureChainsPage />)
    expect(screen.getByText('How chains are built')).toBeInTheDocument()
    expect(container.textContent).not.toContain('—')
  })
})
