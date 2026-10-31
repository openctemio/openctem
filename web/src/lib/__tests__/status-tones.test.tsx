/** The one status registry and its chip: labels from i18n, tone per value, never colour alone. */

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { StatusChip } from '@/features/shared/components/status-chip'
import { STATUS_TONES, statusEntry } from '@/lib/status-tones'
import enCampaigns from '@/lib/i18n/dictionaries/en/remediationCampaigns.json'
import enHub from '@/lib/i18n/dictionaries/en/remediationHub.json'
import enSensors from '@/lib/i18n/dictionaries/en/sensors.json'
import enPageMonitor from '@/lib/i18n/dictionaries/en/pageMonitor.json'

describe('status registry', () => {
  it('names every label key in the English catalog', () => {
    const keys = new Set([
      ...Object.keys(enCampaigns),
      ...Object.keys(enHub),
      ...Object.keys(enSensors),
      ...Object.keys(enPageMonitor),
    ])
    for (const domain of Object.values(STATUS_TONES)) {
      for (const entry of Object.values(domain)) expect(keys.has(entry.labelKey)).toBe(true)
    }
  })

  it('reads a draft campaign as Draft and an active one as Active, as lozenges', () => {
    render(
      <>
        <StatusChip domain="remediationCampaign" value="draft" />
        <StatusChip domain="remediationCampaign" value="active" />
      </>
    )
    const draft = screen.getByText('Draft').closest('[data-slot="status-lozenge"]')
    const active = screen.getByText('Active').closest('[data-slot="status-lozenge"]')
    expect(draft).toHaveAttribute('data-tone', 'triage')
    expect(active).toHaveAttribute('data-tone', 'progress')
    expect(draft?.querySelector('svg')).not.toBeNull()
  })

  it('maps every old tone to its lozenge category', () => {
    const expected = {
      remediationTask: {
        open: 'open',
        in_progress: 'progress',
        verifying: 'progress',
        on_hold: 'waiting',
        done: 'resolved',
        closed_unverified: 'closed',
        canceled: 'closed',
        archived: 'closed',
      },
      remediationCampaign: {
        draft: 'triage',
        active: 'progress',
        completed: 'resolved',
        canceled: 'closed',
      },
    } as const
    for (const [domain, values] of Object.entries(expected))
      for (const [value, tone] of Object.entries(values))
        expect(
          statusEntry(domain as keyof typeof STATUS_TONES, value)?.tone,
          `${domain}.${value}`
        ).toBe(tone)
  })

  it('never uses a red or hand-written colour: the registry holds no classes', () => {
    for (const domain of Object.values(STATUS_TONES))
      for (const entry of Object.values(domain))
        expect(Object.keys(entry).sort()).toEqual(['icon', 'labelKey', 'tone'])
  })

  it('gives task states their tones', () => {
    expect(statusEntry('remediationTask', 'on_hold')?.tone).toBe('waiting')
    expect(statusEntry('remediationTask', 'done')?.tone).toBe('resolved')
    expect(statusEntry('remediationTask', 'toString')).toBeUndefined()
  })

  it('shows an unknown value humanized as an untouched lozenge', () => {
    render(<StatusChip domain="remediationCampaign" value="paused_by_admin" />)
    expect(screen.getByText(/paused/i).closest('[data-slot="status-lozenge"]')).toHaveAttribute(
      'data-tone',
      'triage'
    )
  })
})
