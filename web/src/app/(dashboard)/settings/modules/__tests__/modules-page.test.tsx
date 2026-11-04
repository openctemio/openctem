/**
 * Settings > Modules (research/394 §4): groups open, dependencies written
 * out, a preview before saving that turns dependents off together, locks
 * with their reason, search and state filter, read-only for members.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
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
const perms = vi.hoisted(() => ({ canEdit: true }))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  Can: ({ children }: { children: ReactNode }) => <>{children}</>,
  useCanMutate: () => perms.canEdit,
  useHasPermission: () => false,
}))

const updateModules = vi.hoisted(() => vi.fn())
const state = vi.hoisted(() => ({ modules: [] as Record<string, unknown>[] }))
const mod = (id: string, over: Record<string, unknown> = {}) => ({
  id,
  name: `api ${id}`,
  category: 'scoping',
  is_core: false,
  entitled: true,
  is_enabled: true,
  display_order: 1,
  release_status: 'released',
  ...over,
})
vi.mock('@/features/organization/api/use-tenant-modules', () => ({
  useTenantModules: () => ({
    modules: state.modules,
    isLoading: false,
    error: undefined,
    mutate: vi.fn(),
  }),
  useUpdateTenantModules: () => ({ updateModules, isUpdating: false }),
  useResetTenantModules: () => ({ resetModules: vi.fn(), isResetting: false }),
  useModuleDependencyGraph: () => ({
    edges: [
      { from: 'scope_config', to: 'assets', type: 'hard', reason: '' },
      { from: 'ctem_cycles', to: 'scope_config', type: 'hard', reason: '' },
      { from: 'control_testing', to: 'compensating_controls', type: 'hard', reason: '' },
      { from: 'compliance', to: 'findings', type: 'soft', reason: '' },
    ],
  }),
  useModuleRealtimeInvalidation: vi.fn(),
}))

import ModulesPage from '../page'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

function renderPage(locale = 'en') {
  return render(
    <I18nProvider locale={locale}>
      <ModulesPage />
    </I18nProvider>
  )
}
const row = (id: string) => document.querySelector(`[data-module="${id}"]`) as HTMLElement

beforeEach(() => {
  perms.canEdit = true
  updateModules.mockReset().mockResolvedValue(undefined)
  window.history.replaceState(null, '', '/settings/modules')
  state.modules = [
    mod('assets', { is_core: true, category: 'core' }),
    mod('findings', { is_core: true, category: 'core' }),
    mod('scope_config'),
    mod('ctem_cycles'),
    mod('compliance', { category: 'compliance' }),
    mod('compensating_controls', { category: 'validation', is_enabled: false, entitled: false }),
    mod('control_testing', { category: 'validation', is_enabled: false }),
    mod('pentest', { category: 'validation', release_status: 'beta' }),
  ]
})

describe('modules page', () => {
  it('shows every group open, translated names, and dependencies by name', async () => {
    renderPage()
    expect(await screen.findByRole('heading', { name: 'Scoping' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Reporting and compliance' })).toBeInTheDocument()
    expect(screen.getByText('Always on')).toBeInTheDocument()
    expect(screen.getByText('Assets, Findings')).toBeInTheDocument()
    expect(row('scope_config')).toHaveTextContent('Scope')
    expect(row('scope_config')).toHaveTextContent('Required by CTEM cycles')
    expect(row('ctem_cycles')).toHaveTextContent('Requires Scope')
    // Core requirements are always on: not written out.
    expect(row('scope_config')).not.toHaveTextContent('Requires Assets')
    // No category chip inside its own group, no API text when the catalog knows the module.
    expect(screen.queryByText('compliance')).not.toBeInTheDocument()
    expect(screen.queryByText('api scope_config')).not.toBeInTheDocument()
    expect(within(row('scope_config')).getByRole('switch', { name: 'Scope' })).toBeChecked()
  })

  it('turning a module off previews its dependents and saves them together', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(screen.getByRole('switch', { name: 'Scope' }))
    expect(row('ctem_cycles')).toHaveTextContent('Turns off with Scope')
    expect(within(row('ctem_cycles')).getByRole('switch')).not.toBeChecked()

    await user.click(screen.getByRole('button', { name: /^Save/ }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Turn off 2 modules?')
    expect(dialog).toHaveTextContent('Also turning off, because they need it')
    expect(dialog).toHaveTextContent('Needs Scope')
    expect(dialog).toHaveTextContent('scheduled jobs')
    expect(dialog).toHaveTextContent('data is kept')
    expect(updateModules).not.toHaveBeenCalled()

    await user.click(within(dialog).getByRole('button', { name: 'Turn off all 2 together' }))
    await waitFor(() =>
      expect(updateModules).toHaveBeenCalledWith({
        modules: [
          { module_id: 'scope_config', is_enabled: false },
          { module_id: 'ctem_cycles', is_enabled: false },
        ],
      })
    )
  })

  it('uses the singular for one module', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.click(screen.getByRole('switch', { name: 'Compliance' }))
    await user.click(screen.getByRole('button', { name: /^Save/ }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Turn off 1 module?')
    expect(within(dialog).getByRole('button', { name: 'Turn off 1 module' })).toBeInTheDocument()
  })

  it('turning a module on alone saves without a dialog', async () => {
    const user = userEvent.setup()
    state.modules = state.modules.map((m) => (m.id === 'pentest' ? { ...m, is_enabled: false } : m))
    renderPage()
    await user.click(screen.getByRole('switch', { name: 'Penetration testing' }))
    await user.click(screen.getByRole('button', { name: /^Save/ }))
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
    await waitFor(() =>
      expect(updateModules).toHaveBeenCalledWith({
        modules: [{ module_id: 'pentest', is_enabled: true }],
      })
    )
  })

  it('locks a module the organization does not have, and its dependents, with the reason', () => {
    renderPage()
    expect(within(row('compensating_controls')).getByRole('switch')).toBeDisabled()
    expect(row('compensating_controls')).toHaveTextContent('Not available for this organization')
    expect(within(row('control_testing')).getByRole('switch')).toBeDisabled()
    expect(row('control_testing')).toHaveTextContent(
      'Needs Compensating controls, which this organization does not have.'
    )
  })

  it('shows a module turned off by the installation, and degraded health', () => {
    state.modules = state.modules.map((m) =>
      m.id === 'compliance'
        ? { ...m, is_enabled: false, reason: 'disabled_by_platform' }
        : m.id === 'pentest'
          ? { ...m, health: 'degraded', health_detail: 'The catalog is behind by 2 days.' }
          : m
    )
    renderPage()
    expect(within(row('compliance')).getByRole('switch')).toBeDisabled()
    expect(row('compliance')).toHaveTextContent('Turned off for the whole installation')
    expect(row('pentest')).toHaveTextContent('Degraded')
    expect(row('pentest')).toHaveTextContent('The catalog is behind by 2 days.')
  })

  it('search and the state filter narrow the list; nothing left offers a way back', async () => {
    const user = userEvent.setup()
    renderPage()
    await user.type(screen.getByRole('searchbox', { name: 'Search modules' }), 'penetration')
    expect(row('pentest')).toBeInTheDocument()
    expect(row('scope_config')).toBeNull()
    expect(screen.queryByRole('heading', { name: 'Scoping' })).not.toBeInTheDocument()

    await user.clear(screen.getByRole('searchbox', { name: 'Search modules' }))
    await user.type(screen.getByRole('searchbox', { name: 'Search modules' }), 'zzzz')
    expect(screen.getByText('No modules match')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Show all modules' }))
    expect(row('scope_config')).toBeInTheDocument()
  })

  it('counts what is on', () => {
    renderPage()
    expect(screen.getAllByText('4 of 6 on').length).toBeGreaterThan(0)
    expect(screen.getByText('2 of 2 on')).toBeInTheDocument()
  })

  it('lists the parts of an always-on module behind a disclosure, and saves a part', async () => {
    const user = userEvent.setup()
    state.modules = [
      ...state.modules,
      mod('integrations', {
        is_core: true,
        category: 'settings',
        sub_modules: [
          { id: 'integrations.scm', name: 'SCM', release_status: 'released', is_enabled: true },
          { id: 'integrations.siem', name: 'SIEM', release_status: 'released', is_enabled: false },
        ],
      }),
    ]
    renderPage()
    expect(screen.queryByRole('switch', { name: 'Code hosts' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '1 of 2 parts on' }))
    await user.click(screen.getByRole('switch', { name: 'SIEM' }))
    await user.click(screen.getByRole('button', { name: /^Save/ }))
    await waitFor(() =>
      expect(updateModules).toHaveBeenCalledWith({
        modules: [{ module_id: 'integrations.siem', is_enabled: true }],
      })
    )
  })

  it('is read-only for a member who may not change modules', () => {
    perms.canEdit = false
    renderPage()
    expect(screen.getByText(/Only administrators can change them/)).toBeInTheDocument()
    for (const sw of screen.getAllByRole('switch')) expect(sw).toBeDisabled()
  })
})
