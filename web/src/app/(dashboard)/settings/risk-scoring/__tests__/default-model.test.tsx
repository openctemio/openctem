import { describe, it, expect, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

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
const api = vi.hoisted(() => ({
  preview: vi.fn(),
  update: vi.fn(),
  recalc: vi.fn(),
  presets: [] as unknown[],
  priorityRules: false,
}))
vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

vi.mock('@/features/organization/api/use-risk-scoring-settings', () => ({
  useRiskScoringSettings: () => ({
    settings: settings.current,
    isLoading: false,
    error: null,
    mutate: vi.fn(async () => settings.current),
  }),
  useUpdateRiskScoring: () => ({ updateRiskScoring: api.update, isUpdating: false }),
  useRiskScoringPreview: () => ({ previewChanges: api.preview, isPreviewing: false }),
  useRecalculateRiskScores: () => ({ recalculate: api.recalc, isRecalculating: false }),
  useRiskScoringPresets: () => ({ presets: api.presets }),
}))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
vi.mock('@/lib/permissions', () => ({
  useHasPermission: () => api.priorityRules,
  Permission: {},
}))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: () => api.priorityRules,
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))

const { default: Page } = await import('../page')
const { rebalanceWeights } =
  await import('@/features/organization/components/risk-scoring-sections')

function show(
  extra: Record<string, unknown> = {},
  opts: { presets?: unknown[]; rules?: boolean } = {}
) {
  settings.current = { ...base, score_composition_mode: 'multiply', ...extra }
  api.preview.mockReset()
  api.update.mockReset()
  api.priorityRules = opts.rules ?? false
  api.presets = opts.presets ?? []
  return render(<Page />)
}

const field = (name: string) => screen.getByRole('spinbutton', { name })

describe('risk scoring: models', () => {
  it('shows the stored model in the composition select and hides the knobs it ignores', () => {
    show({ score_composition_mode: 'likelihood_impact' })
    expect(screen.getByRole('combobox', { name: 'Score composition' })).toHaveTextContent(
      'Likelihood × impact (default)'
    )
    expect(screen.queryByText('Component weights')).not.toBeInTheDocument()
    expect(screen.queryByText('Finding and CTEM impact')).not.toBeInTheDocument()
    expect(screen.queryByText('Multiplier')).not.toBeInTheDocument()
    expect(screen.getByText('Exposure scores')).toBeInTheDocument()
  })

  it('keeps the weighted controls for a weighted composition', () => {
    show()
    expect(screen.getByRole('combobox', { name: 'Score composition' })).toHaveTextContent(
      'Standard (multiply)'
    )
    expect(screen.getByText('Component weights')).toBeInTheDocument()
    expect(screen.getByText('Exposure scores and multipliers')).toBeInTheDocument()
    expect(screen.getByText('Finding and CTEM impact')).toBeInTheDocument()
  })

  it('ties every number field to its label', () => {
    show()
    for (const input of document.querySelectorAll('input[type="number"]')) {
      expect(document.querySelector(`label[for="${input.id}"]`), input.outerHTML).not.toBeNull()
    }
  })
})

describe('risk scoring: saving', () => {
  it('has no save bar until something changes, then the bar names the change', () => {
    show()
    expect(screen.queryByRole('region', { name: 'Unsaved changes' })).not.toBeInTheDocument()
    fireEvent.change(field('Low (min)'), { target: { value: '25' } })
    fireEvent.blur(field('Low (min)'))
    expect(screen.getByRole('region', { name: 'Unsaved changes' })).toBeInTheDocument()
    expect(screen.getByText('1 unsaved change')).toBeInTheDocument()
  })

  it('changing a value back removes the bar and keeps the saved preset', () => {
    show()
    const input = field('Low (min)')
    fireEvent.change(input, { target: { value: '25' } })
    fireEvent.blur(input)
    expect(screen.getByRole('region', { name: 'Unsaved changes' })).toBeInTheDocument()
    fireEvent.change(input, { target: { value: '20' } })
    fireEvent.blur(input)
    expect(screen.queryByRole('region', { name: 'Unsaved changes' })).not.toBeInTheDocument()
  })

  it('Save shows the impact first and applies only from the review', async () => {
    show()
    api.preview.mockResolvedValue({
      assets: {
        total_assets: 3,
        changed: 1,
        raised: 1,
        lowered: 0,
        changed_bands: 0,
        band_changes: [],
        top_changes: [],
      },
      affects_priority: false,
    })
    fireEvent.change(field('High (min)'), { target: { value: '65' } })
    fireEvent.blur(field('High (min)'))
    await userEvent.click(screen.getByRole('button', { name: /Save changes/ }))
    await waitFor(() => expect(api.preview).toHaveBeenCalled())
    expect(api.update).not.toHaveBeenCalled()
    expect(await screen.findByText('Review the impact')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Apply changes' }))
    await waitFor(() => expect(api.update).toHaveBeenCalled())
    expect(api.update.mock.calls[0][0].risk_levels.high_min).toBe(65)
  })

  it('refuses to save thresholds that are out of order and says why', () => {
    show()
    fireEvent.change(field('Medium (min)'), { target: { value: '70' } })
    fireEvent.blur(field('Medium (min)'))
    expect(screen.getByRole('alert')).toHaveTextContent('Must be ordered')
    expect(screen.getByRole('button', { name: /Save changes/ })).toBeDisabled()
  })

  it('Discard brings back the saved values', async () => {
    show()
    fireEvent.change(field('Low (min)'), { target: { value: '30' } })
    fireEvent.blur(field('Low (min)'))
    await userEvent.click(screen.getByRole('button', { name: 'Discard' }))
    expect(field('Low (min)')).toHaveValue(20)
    expect(screen.queryByRole('region', { name: 'Unsaved changes' })).not.toBeInTheDocument()
  })
})

describe('risk scoring: presets, recalculate, priority rules', () => {
  it('picking a preset loads its values as unsaved changes', async () => {
    const banking = {
      ...base,
      preset: 'banking',
      score_composition_mode: 'multiply',
      risk_levels: { critical_min: 90, high_min: 70, medium_min: 50, low_min: 30 },
    }
    show(
      { preset: 'default' },
      {
        presets: [
          { name: 'default', config: base },
          { name: 'banking', config: banking },
        ],
      }
    )
    await userEvent.click(screen.getByRole('radio', { name: /Banking/ }))
    expect(field('Low (min)')).toHaveValue(30)
    expect(screen.getByRole('region', { name: 'Unsaved changes' })).toBeInTheDocument()
  })

  it('Recalculate is off while changes are unsaved', () => {
    show()
    expect(screen.getByRole('button', { name: /Recalculate/ })).toBeEnabled()
    fireEvent.change(field('Low (min)'), { target: { value: '30' } })
    fireEvent.blur(field('Low (min)'))
    expect(screen.getByRole('button', { name: /Recalculate/ })).toBeDisabled()
    expect(screen.getByText('Save changes before recalculating.')).toBeInTheDocument()
  })

  it('shows the priority rules link only with the permission and the module', () => {
    show()
    expect(screen.queryByRole('link', { name: 'Open priority rules' })).not.toBeInTheDocument()
  })

  it('offers the priority rules link with the permission and the module', () => {
    show({}, { rules: true })
    expect(screen.getByRole('link', { name: 'Open priority rules' })).toHaveAttribute(
      'href',
      '/priority-rules'
    )
  })
})

describe('risk scoring: weights', () => {
  it('always add up to 100 after one moves', () => {
    const w = rebalanceWeights(
      { exposure: 35, criticality: 25, findings: 30, ctem: 10 },
      'exposure',
      60
    )
    expect(w.exposure).toBe(60)
    expect(w.exposure + w.criticality + w.findings + w.ctem).toBe(100)
  })

  it('splits the rest equally when the others are all zero', () => {
    const w = rebalanceWeights(
      { exposure: 100, criticality: 0, findings: 0, ctem: 0 },
      'exposure',
      70
    )
    expect(w).toEqual({ exposure: 70, criticality: 10, findings: 10, ctem: 10 })
  })
})
