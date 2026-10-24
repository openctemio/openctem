/** Turning modules off asks first, naming them and saying their data is kept. */
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
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
const updateModules = vi.hoisted(() => vi.fn().mockResolvedValue(undefined))
const mod = (id: string, over: Record<string, unknown>) => ({
  id,
  name: id === 'assets' ? 'Asset inventory' : id,
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
  useUpdateTenantModules: () => ({ updateModules, isUpdating: false }),
  useResetTenantModules: () => ({ resetModules: vi.fn(), isResetting: false }),
  useModuleDependencyGraph: () => ({ edges: [] }),
  useModuleRealtimeInvalidation: vi.fn(),
}))

import ModulesPage from '../page'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

describe('modules page disable confirmation', () => {
  it('names the modules being turned off and saves only after confirming', async () => {
    const user = userEvent.setup()
    render(
      <I18nProvider locale="en">
        <ModulesPage />
      </I18nProvider>
    )
    // Open every phase group, then switch the feature module off.
    for (const b of screen.queryAllByRole('button', { expanded: false })) await user.click(b)
    const sw = await screen.findByRole('switch', { name: /Asset inventory/ })
    await user.click(sw)
    await user.click(screen.getByRole('button', { name: /^Save/ }))

    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Turn off 1 modules?')
    expect(dialog).toHaveTextContent('Asset inventory')
    expect(dialog).toHaveTextContent('data is kept')
    expect(updateModules).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Turn off 1 modules' }))
    await waitFor(() =>
      expect(updateModules).toHaveBeenCalledWith({
        modules: [{ module_id: 'assets', is_enabled: false }],
      })
    )
  })
})
