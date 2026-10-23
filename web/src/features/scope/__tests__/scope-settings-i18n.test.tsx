/** The scope policy form renders Vietnamese for a Vietnamese reader. */
import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { I18nProvider } from '@/context/i18n-provider'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useHasPermission: () => true,
  usePermissions: () => ({ isOwner: () => true, can: () => true }),
}))
vi.mock('../api/use-scope-api', () => ({
  updateScopeSettings: vi.fn(),
  updateScopeIntrusiveSettings: vi.fn(),
}))

import { ScopeSettingsForm } from '../components/scope-settings-form'

describe('scope policy (vi)', () => {
  it('translates the settings', () => {
    render(
      <I18nProvider locale="vi">
        <ScopeSettingsForm
          settings={
            { admin_count: 2, effective_widening_approvals: 1, one_off_targets: 'admins' } as never
          }
        />
      </I18nProvider>
    )
    expect(screen.getByText('Đang có hiệu lực')).toBeInTheDocument()
    expect(screen.getByText('Số phê duyệt cần để mở rộng')).toBeInTheDocument()
    expect(screen.getByText('Kiểm tra phạm vi')).toBeInTheDocument()
    expect(screen.getByText('Mục dùng một lần')).toBeInTheDocument()
    expect(screen.getByText('Thời hạn dài nhất của mục xâm nhập')).toBeInTheDocument()
    expect(screen.queryByText('In effect now')).not.toBeInTheDocument()
    expect(screen.queryByText('Approvals a widening needs')).not.toBeInTheDocument()
    expect(screen.queryByText('Longest intrusive entry')).not.toBeInTheDocument()
  })
})
