/**
 * The ticket mapping editor: deleting a mapping needs its name, and turning
 * dry run off (which starts Jira writes) asks first. Turning it on is one click.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const api = vi.hoisted(() => ({
  dryRun: false,
  setDryRun: vi.fn(),
  remove: vi.fn(),
  push: vi.fn(),
  // The editor syncs its draft from `data` in an effect, so the mock must return the
  // same object while nothing changed (a fresh object per render loops forever).
  cache: new Map<boolean, unknown>(),
  result(): unknown {
    if (!api.cache.has(api.dryRun)) {
      api.cache.set(api.dryRun, {
        data: {
          profile: {
            id: 'mp1',
            integration_id: 'i1',
            object_kind: 'finding',
            project_id: 'p',
            project_key: 'SEC',
            issue_type_id: '1',
            issue_type: 'Task',
            name: 'Security tasks',
            published_version: 1,
            draft_version: 0,
            dry_run: api.dryRun,
            drifted: false,
            created_at: '',
            updated_at: '',
          },
          published: { version: 1, spec: {} },
        },
        error: undefined,
        isLoading: false,
        mutate: async () => undefined,
      })
    }
    return api.cache.get(api.dryRun)
  },
}))

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: api.push, replace: vi.fn() }) }))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: ReactNode }) => <main>{children}</main>,
  useBreadcrumbTitle: () => undefined,
}))
vi.mock('@/components/link', () => ({
  default: ({ children, href }: { children: ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: () => true }),
}))
vi.mock('../components/field-mapper', () => ({
  FieldMapper: () => null,
  MappingSettingsBar: () => null,
}))
vi.mock('../components/workflow-mapper', () => ({ WorkflowMapper: () => null }))
vi.mock('../components/mapping-preview', () => ({ MappingPreview: () => null }))
vi.mock('../components/mapping-history', () => ({ MappingHistory: () => null }))
vi.mock('../api/use-ticket-mapping-api', () => ({
  invalidateMappings: vi.fn(async () => undefined),
  useMappingCatalog: () => ({ data: { attributes: [] } }),
  useProjectMeta: () => ({ data: undefined, isLoading: false, mutate: vi.fn() }),
  useMappingProfile: () => api.result(),
  mappingApi: {
    setDryRun: (...a: unknown[]) => api.setDryRun(...a),
    remove: (...a: unknown[]) => api.remove(...a),
    verify: vi.fn(async () => ({ issues: [] })),
    exportUrl: () => '',
  },
}))

import { MappingEditor } from '../components/mapping-editor'

describe('MappingEditor confirmations', () => {
  beforeEach(() => {
    api.dryRun = false
    api.setDryRun.mockReset().mockResolvedValue(undefined)
    api.remove.mockReset().mockResolvedValue(undefined)
  })

  it('turning dry run off asks first and then writes', async () => {
    api.dryRun = true
    const user = userEvent.setup()
    render(<MappingEditor id="mp1" />)
    await user.click(screen.getByRole('switch'))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Turn off dry run for "Security tasks"?')
    expect(dialog).toHaveTextContent('writes to Jira')
    expect(api.setDryRun).not.toHaveBeenCalled()
    await user.click(within(dialog).getByRole('button', { name: 'Turn off dry run' }))
    await waitFor(() => expect(api.setDryRun).toHaveBeenCalledWith('mp1', false))
  })

  it('Cancel keeps dry run on', async () => {
    api.dryRun = true
    const user = userEvent.setup()
    render(<MappingEditor id="mp1" />)
    await user.click(screen.getByRole('switch'))
    await user.click(await screen.findByRole('button', { name: 'Cancel' }))
    expect(api.setDryRun).not.toHaveBeenCalled()
  })

  it('turning dry run on is one click', async () => {
    api.dryRun = false
    const user = userEvent.setup()
    render(<MappingEditor id="mp1" />)
    await user.click(screen.getByRole('switch'))
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
    await waitFor(() => expect(api.setDryRun).toHaveBeenCalledWith('mp1', true))
  })

  it('deleting the mapping needs its name', async () => {
    const user = userEvent.setup()
    render(<MappingEditor id="mp1" />)
    await user.click(screen.getByRole('button', { name: /^Delete$/ }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Delete the mapping "Security tasks"?')
    const confirm = within(dialog).getByRole('button', { name: 'Delete mapping' })
    expect(confirm).toBeDisabled()
    await user.type(within(dialog).getByRole('textbox'), 'Security tasks')
    await user.click(confirm)
    await waitFor(() => expect(api.remove).toHaveBeenCalledWith('mp1'))
  })
})
