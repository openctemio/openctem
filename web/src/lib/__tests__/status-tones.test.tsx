/** The one status registry and its chip: labels from i18n, tone per value, never colour alone. */

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { StatusChip } from '@/features/shared/components/status-chip'
import { STATUS_TONES, statusEntry } from '@/lib/status-tones'
import enCampaigns from '@/lib/i18n/dictionaries/en/remediationCampaigns.json'
import enHub from '@/lib/i18n/dictionaries/en/remediationHub.json'

describe('status registry', () => {
  it('names every label key in the English catalog', () => {
    const keys = new Set([...Object.keys(enCampaigns), ...Object.keys(enHub)])
    for (const domain of Object.values(STATUS_TONES)) {
      for (const entry of Object.values(domain)) expect(keys.has(entry.labelKey)).toBe(true)
    }
  })

  it('reads a draft campaign as Draft and an active one as Active', () => {
    render(
      <>
        <StatusChip domain="remediationCampaign" value="draft" />
        <StatusChip domain="remediationCampaign" value="active" />
      </>
    )
    expect(screen.getByText('Draft')).toHaveAttribute('data-tone', 'neutral')
    expect(screen.getByText('Active')).toHaveAttribute('data-tone', 'progress')
  })

  it('gives task states their tones', () => {
    expect(statusEntry('remediationTask', 'on_hold')?.tone).toBe('warning')
    expect(statusEntry('remediationTask', 'done')?.tone).toBe('success')
    expect(statusEntry('remediationTask', 'toString')).toBeUndefined()
  })

  it('shows an unknown value humanized in the neutral tone', () => {
    render(<StatusChip domain="remediationCampaign" value="paused_by_admin" />)
    expect(screen.getByText(/paused/i)).toHaveAttribute('data-tone', 'neutral')
  })
})
