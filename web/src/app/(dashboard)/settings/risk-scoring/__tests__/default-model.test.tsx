import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

// The weight sliders measure themselves.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const base = {
  preset: 'default',
  weights: { exposure: 35, criticality: 25, findings: 30, ctem: 10 },
  exposure_scores: { public: 100, restricted: 90, private: 75, isolated: 50, unknown: 90 },
  exposure_multipliers: { public: 1.3, restricted: 1.1, private: 1, isolated: 0.9, unknown: 1 },
  criticality_scores: { critical: 100, high: 90, medium: 80, low: 60, none: 80 },
  finding_impact: {
    mode: 'severity_weighted',
    per_finding_points: 5,
    finding_cap: 100,
    severity_weights: { critical: 20, high: 10, medium: 5, low: 2, info: 1 },
  },
  ctem_points: {
    enabled: false,
    internet_accessible: 30,
    public_exposure: 20,
    high_risk_exposure: 30,
    has_pii: 10,
    has_phi: 15,
  },
  risk_levels: { critical_min: 80, high_min: 60, medium_min: 40, low_min: 20 },
}
const settings = vi.hoisted(() => ({ current: {} as Record<string, unknown> }))

vi.mock('@/features/organization/api/use-risk-scoring-settings', () => ({
  useRiskScoringSettings: () => ({
    settings: settings.current,
    isLoading: false,
    error: null,
    mutate: vi.fn(),
  }),
  useUpdateRiskScoring: () => ({ updateRiskScoring: vi.fn(), isUpdating: false }),
  useRiskScoringPreview: () => ({ previewChanges: vi.fn(), isPreviewing: false }),
  useRecalculateRiskScores: () => ({ recalculate: vi.fn(), isRecalculating: false }),
  useRiskScoringPresets: () => ({ presets: [] }),
}))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
vi.mock('@/lib/permissions', () => ({ useHasPermission: () => false, Permission: {} }))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({ useModuleEnabled: () => false }))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))

const { default: Page } = await import('../page')

describe('risk scoring: the default likelihood × impact model', () => {
  it('shows the stored model in the composition select and hides the knobs it ignores', () => {
    settings.current = { ...base, score_composition_mode: 'likelihood_impact' }
    render(<Page />)
    expect(screen.getByRole('combobox', { name: 'Score composition' })).toHaveTextContent(
      'Likelihood × impact (default)'
    )
    expect(screen.getByText('Likelihood × impact model')).toBeInTheDocument()
    expect(screen.queryByText('Component weights')).not.toBeInTheDocument()
    expect(screen.queryByText('Finding and CTEM impact')).not.toBeInTheDocument()
    expect(screen.queryByText(/Multipliers \(0\.1/)).not.toBeInTheDocument()
    // Its factors stay editable.
    expect(screen.getByText('Exposure scores')).toBeInTheDocument()
  })

  it('keeps the weighted controls for a weighted composition', () => {
    settings.current = { ...base, score_composition_mode: 'multiply' }
    render(<Page />)
    expect(screen.getByRole('combobox', { name: 'Score composition' })).toHaveTextContent(
      'Standard (multiply)'
    )
    expect(screen.getByText('Component weights')).toBeInTheDocument()
    expect(screen.queryByText('Likelihood × impact model')).not.toBeInTheDocument()
  })

  it('ties every number field to its label', () => {
    settings.current = { ...base, score_composition_mode: 'multiply' }
    render(<Page />)
    for (const input of document.querySelectorAll('input[type="number"]')) {
      expect(document.querySelector(`label[for="${input.id}"]`), input.outerHTML).not.toBeNull()
    }
  })
})
