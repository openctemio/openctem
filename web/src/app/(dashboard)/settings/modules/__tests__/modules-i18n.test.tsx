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
    modules: [
      mod('assets', { is_core: true, category: 'core' }),
      mod('scope_config', { category: 'scoping' }),
      mod('compliance', { category: 'compliance' }),
    ],
    summary: { total: 2, enabled: 2, disabled: 0, core: 1 },
    isLoading: false,
    error: undefined,
    mutate: vi.fn(),
  }),
  useUpdateTenantModules: () => ({ updateModules: vi.fn(), isUpdating: false }),
  useResetTenantModules: () => ({ resetModules: vi.fn(), isResetting: false }),
  useModuleDependencyGraph: () => ({
    edges: [{ from: 'compliance', to: 'scope_config', type: 'hard', reason: '' }],
  }),
  useModuleRealtimeInvalidation: vi.fn(),
}))

import ModulesPage from '../page'

describe('modules page (vi)', () => {
  it('translates headings and labels', () => {
    render(
      <I18nProvider locale="vi">
        <ModulesPage />
      </I18nProvider>
    )
    expect(screen.getByText('Luôn bật')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Báo cáo và tuân thủ' })).toBeInTheDocument()
    expect(screen.getByText('Đặt lại mặc định')).toBeInTheDocument()
    // Module names, descriptions and dependency lines come from the catalog.
    expect(screen.getByRole('switch', { name: 'Phạm vi' })).toBeInTheDocument()
    expect(screen.getByText('Cần Phạm vi')).toBeInTheDocument()
    expect(screen.getByText(/Khung tuân thủ/)).toBeInTheDocument()
    expect(screen.queryByText('scope_config')).not.toBeInTheDocument()
    expect(screen.queryByText('Always on')).not.toBeInTheDocument()
    expect(screen.queryByText('Reset to defaults')).not.toBeInTheDocument()
  })
})
