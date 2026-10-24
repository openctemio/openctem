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
  it('renders a load error inside the page stack', () => {
    state.current = {
      chains: undefined,
      error: new Error('boom'),
      isLoading: false,
      mutate: vi.fn(),
    }
    render(<ExposureChainsPage />)
    const alert = screen.getByRole('alert')
    expect(alert.parentElement).toHaveAttribute('data-slot', 'page-stack')
    expect(alert.parentElement?.querySelector('.mt-5')).toBeNull()
  })

  it('renders the no-relationships state inside the page stack', () => {
    state.current = {
      chains: { summary: { hasRelationshipData: false }, chains: [] },
      error: undefined,
      isLoading: false,
      mutate: vi.fn(),
    }
    const { container } = render(<ExposureChainsPage />)
    expect(
      screen.getByText('No relationship data yet').closest('[data-slot="page-stack"]')
    ).not.toBeNull()
    expect(container.querySelector('.mt-5')).toBeNull()
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
