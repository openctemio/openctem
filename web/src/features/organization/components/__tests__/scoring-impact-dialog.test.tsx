import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ScoringImpactDialog } from '../scoring-impact-dialog'
import type { RiskScoringPreviewResponse } from '../../types/settings.types'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const preview: RiskScoringPreviewResponse = {
  assets: {
    total_assets: 120,
    changed: 7,
    raised: 5,
    lowered: 2,
    changed_bands: 3,
    band_changes: [{ from: 'medium', to: 'high', count: 3 }],
    top_changes: [
      {
        asset_id: 'a1',
        asset_name: 'api.example.com',
        asset_type: 'domain',
        current_score: 55,
        new_score: 68,
        current_level: 'medium',
        new_level: 'high',
      },
    ],
  },
  affects_priority: true,
  findings: {
    open_findings: 40,
    changed: 4,
    raised: 4,
    lowered: 0,
    class_changes: [{ from: 'P3', to: 'P2', count: 4 }],
    deadlines_tightened: 2,
    tickets_affected: 1,
    manual_overrides_kept: 1,
  },
}

function renderDialog(over: Partial<React.ComponentProps<typeof ScoringImpactDialog>> = {}) {
  const onApply = vi.fn()
  render(
    <ScoringImpactDialog
      open
      onOpenChange={vi.fn()}
      preview={preview}
      loading={false}
      error={null}
      applying={false}
      onApply={onApply}
      {...over}
    />
  )
  return { onApply }
}

describe('ScoringImpactDialog', () => {
  it('shows the whole-organization asset and finding impact', () => {
    renderDialog()
    expect(screen.getByText('120')).toBeInTheDocument()
    expect(screen.getByText('3 assets')).toBeInTheDocument()
    expect(screen.getByText('api.example.com')).toBeInTheDocument()
    expect(screen.getByText('4 findings')).toBeInTheDocument()
    expect(screen.getByText('Deadlines move earlier')).toBeInTheDocument()
    expect(screen.getByText(/keep it/)).toBeInTheDocument()
    expect(
      screen.getByText(/Closed findings, past trends and reports keep their values/)
    ).toBeInTheDocument()
  })

  it('applies only from the review', async () => {
    const { onApply } = renderDialog()
    await userEvent.click(screen.getByRole('button', { name: 'Apply changes' }))
    expect(onApply).toHaveBeenCalledTimes(1)
  })

  it('cannot apply before the impact is known', () => {
    renderDialog({ preview: null, loading: true })
    expect(screen.getByRole('button', { name: 'Apply changes' })).toBeDisabled()
    expect(screen.getByText('Computing the impact…')).toBeInTheDocument()
  })

  it('hides the finding section when the priority settings did not change', () => {
    renderDialog({ preview: { ...preview, affects_priority: false, findings: undefined } })
    expect(screen.queryByText('Open finding priorities')).not.toBeInTheDocument()
  })
})
