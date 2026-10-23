/**
 * The asset lifecycle form and its dry-run dialog render Vietnamese for a
 * Vietnamese reader, with no leftover English.
 */
import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SWRConfig } from 'swr'
import { I18nProvider } from '@/context/i18n-provider'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
vi.mock('../api', () => ({
  updateAssetLifecycleSettings: vi.fn(),
  runAssetLifecycleDryRun: vi.fn(),
}))

import { LifecycleSettingsForm } from '../components/lifecycle-settings-form'
import { DryRunDialog } from '../components/dry-run-dialog'
import { DEFAULT_LIFECYCLE_SETTINGS } from '../types'

const wrap = (ui: React.ReactNode) =>
  render(
    <SWRConfig value={{ provider: () => new Map() }}>
      <I18nProvider locale="vi">{ui}</I18nProvider>
    </SWRConfig>
  )

describe('asset lifecycle settings (vi)', () => {
  it('translates the form', () => {
    wrap(
      <LifecycleSettingsForm
        initial={{ ...DEFAULT_LIFECYCLE_SETTINGS, enabled: true, dry_run_completed_at: null }}
        formId="f"
        dryRunOpen={false}
        onDryRunOpenChange={() => {}}
      />
    )
    expect(screen.getByText('Cần chạy thử trước khi bật')).toBeInTheDocument()
    expect(screen.getByLabelText('Ngưỡng tài sản cũ (ngày)')).toBeInTheDocument()
    expect(screen.getByLabelText('Ân hạn khi mới phát hiện (ngày)')).toBeInTheDocument()
    expect(screen.getByText('Loại nguồn được loại trừ')).toBeInTheDocument()
    expect(screen.queryByText('Dry run required before enabling')).not.toBeInTheDocument()
    expect(screen.queryByText('Stale threshold (days)')).not.toBeInTheDocument()
    expect(screen.queryByText('Excluded source types')).not.toBeInTheDocument()
  })

  it('translates the dry-run dialog', () => {
    wrap(<DryRunDialog open onOpenChange={() => {}} />)
    expect(screen.getByText('Chạy thử vòng đời')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Chạy ngay' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Đóng', hidden: true })).toBeInTheDocument()
    expect(screen.queryByText('Lifecycle dry-run')).not.toBeInTheDocument()
  })
})
