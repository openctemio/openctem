/**
 * The threat-model landing and detail pieces are translated: with the console
 * locale set to Vietnamese the models list, the stats strip and the status
 * labels read in Vietnamese, and dates follow the locale.
 */
import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { I18nProvider } from '@/context/i18n-provider'

vi.mock('@/features/shared', async (orig) => ({
  ...(await orig<object>()),
  EmptyState: ({ title }: { title: string }) => <p>{title}</p>,
}))

import { ExistingModels } from '../components/existing-models'
import { getThreatStatusStyle } from '../lib/threat-status'
import { formatDateTime } from '../lib/format-date'
import type { ThreatModelSummary } from '../types'

const model: ThreatModelSummary = {
  id: 'm1',
  tenant_id: 't1',
  scope_type: 'crown_jewel',
  scope_ref_id: 'a1',
  name: 'Payments',
  generated_at: '2026-10-01T10:00:00Z',
  technique_dataset_version: 'v15',
  threats_total: 12,
  threats_open: 3,
  threats_mitigated: 4,
  threats_covered: 2,
  coverage_pct: 50,
  created_at: '2026-10-01T10:00:00Z',
  updated_at: '2026-10-01T10:00:00Z',
}

const renderList = (locale: string, models: ThreatModelSummary[]) =>
  render(
    <I18nProvider locale={locale}>
      <ExistingModels models={models} onOpen={() => {}} />
    </I18nProvider>
  )

describe('threat model i18n', () => {
  it('renders the models list in Vietnamese', () => {
    renderList('vi', [model])
    expect(screen.getByText('Mô hình mối đe dọa')).toBeTruthy()
    expect(screen.getByText('3 đang mở')).toBeTruthy()
    expect(screen.getByText('12 mối đe dọa')).toBeTruthy()
    expect(screen.getByText('Bao phủ 50%')).toBeTruthy()
  })

  it('renders the list in English', () => {
    renderList('en', [model])
    expect(screen.getByText('3 open')).toBeTruthy()
    expect(screen.getByText('12 threats')).toBeTruthy()
  })

  it('shows the Vietnamese empty state', () => {
    renderList('vi', [])
    expect(screen.getByText('Chưa có mô hình mối đe dọa')).toBeTruthy()
  })

  it('status labels are keys, not raw English', () => {
    expect(getThreatStatusStyle('open').labelKey).toBe('threatModel.status.open')
  })

  it('formats the time in the console locale', () => {
    expect(formatDateTime('2026-10-01T10:00:00Z', 'vi')).not.toBe(
      formatDateTime('2026-10-01T10:00:00Z', 'en-US')
    )
    expect(formatDateTime('not a date', 'vi')).toBe('not a date')
  })
})
