/** The modules settings page renders Vietnamese for a Vietnamese reader. */
import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ReactNode } from 'react'
import { I18nProvider } from '@/context/i18n-provider'

vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: ReactNode }) => <main>{children}</main>,
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), warning: vi.fn() } }))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
vi.mock('@/context/bootstrap-provider', () => ({
  useBootstrapContext: () => ({ refreshModules: vi.fn(), data: undefined }),
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  Can: ({ children }: { children: ReactNode }) => <>{children}</>,
}))
const mod = (id: string, over: Record<string, unknown>) => ({
  id,
  name: id,
  category: 'discovery',
  is_core: false,
  is_enabled: true,
  display_order: 1,
  release_status: 'beta',
  ...over,
})
vi.mock('@/features/organization/api/use-tenant-modules', () => ({
  useTenantModules: () => ({
    modules: [mod('core1', { is_core: true, category: 'core' }), mod('assets', {})],
    summary: { total: 2, enabled: 2, disabled: 0, core: 1 },
    isLoading: false,
    error: undefined,
    mutate: vi.fn(),
  }),
  useUpdateTenantModules: () => ({ updateModules: vi.fn(), isUpdating: false }),
  useResetTenantModules: () => ({ resetModules: vi.fn(), isResetting: false }),
  useModuleDependencyGraph: () => ({ edges: [] }),
  useModuleRealtimeInvalidation: vi.fn(),
}))

import ModulesPage from '../page'

describe('modules page (vi)', () => {
  it('translates headings, metrics and labels', () => {
    render(
      <I18nProvider locale="vi">
        <ModulesPage />
      </I18nProvider>
    )
    expect(screen.getByText('Mô-đun lõi')).toBeInTheDocument()
    expect(screen.getByText('Tinh chỉnh tính năng')).toBeInTheDocument()
    expect(screen.getByText('Tổng số mô-đun')).toBeInTheDocument()
    expect(screen.getByText('Xóa các thay đổi của tôi')).toBeInTheDocument()
    expect(screen.queryByText('Core modules')).not.toBeInTheDocument()
    expect(screen.queryByText('Fine-tune features')).not.toBeInTheDocument()
    expect(screen.queryByText('Total modules')).not.toBeInTheDocument()
  })
})
