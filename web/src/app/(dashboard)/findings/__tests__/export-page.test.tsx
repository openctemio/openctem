import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const listCalls: Array<Record<string, unknown>> = []
const listTotal = { value: 25000 }
const statsCalls: Array<Record<string, unknown> | undefined> = []
const routerPush = vi.fn()

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: routerPush, replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => '/findings',
  useSearchParams: () => new URLSearchParams(window.location.search),
}))

vi.mock('swr', () => ({
  default: vi.fn(() => ({ data: undefined, error: undefined, isLoading: false, mutate: vi.fn() })),
  mutate: vi.fn(),
  useSWRConfig: () => ({ mutate: vi.fn() }),
}))

vi.mock('@/features/findings/api/use-findings-api', async (orig) => ({
  ...(await orig<typeof import('@/features/findings/api/use-findings-api')>()),
  useFindingApi: () => ({ data: undefined }),
  useFindingsApi: (filters: Record<string, unknown>) => {
    listCalls.push(filters)
    return {
      data: { data: [], total: listTotal.value, page: 1, per_page: 20 },
      error: undefined,
      isLoading: false,
      mutate: vi.fn(),
    }
  },
  useFindingStatsApi: (filters?: Record<string, unknown>) => {
    statsCalls.push(filters)
    return {
      data: {
        total: 18,
        by_severity: {},
        by_status: {},
        open_count: 12,
        by_state: { open: 12, fixed: 4, dispositioned: 2, all: 18 },
      },
      isLoading: false,
      mutate: vi.fn(),
    }
  },
  invalidateFindingsCache: vi.fn(),
}))

vi.mock('@/features/config/api/finding-source-api', () => ({
  useFindingSourcesApi: () => ({ data: undefined }),
  groupFindingSourcesByCategory: () => [],
}))

const perms = { exportAllowed: true }
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({
    hasPermission: (p: string) => p !== 'findings:export' || perms.exportAllowed,
  }),
}))

const exportCalls: Array<{ path: string; format: string }> = []
const exportResult: { value: unknown } = { value: { filename: 'f.csv', maxRows: 10000 } }
vi.mock('@/features/findings/api/export-findings', async (orig) => ({
  ...(await orig<typeof import('@/features/findings/api/export-findings')>()),
  downloadFindingsExport: vi.fn((path: string, format: string) => {
    exportCalls.push({ path, format })
    return exportResult.value instanceof Error
      ? Promise.reject(exportResult.value)
      : Promise.resolve(exportResult.value)
  }),
}))
const toasts = vi.hoisted(() => ({ success: vi.fn(), warning: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast: toasts }))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: () => true,
}))
vi.mock('@/features/saved-views/components/saved-views-menu', () => ({
  SavedViewsMenu: () => null,
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))

// Dialogs and drawers are closed and have their own data stacks.
vi.mock('@/features/findings/components/auto-assign-dialog', () => ({
  AutoAssignDialog: () => null,
}))
vi.mock('@/features/findings/components/mark-fixed-dialog', () => ({ MarkFixedDialog: () => null }))
vi.mock('@/features/findings/components/create-ticket-dialog', () => ({
  CreateTicketDialog: () => null,
}))
vi.mock('@/features/remediation-hub/components/add-findings-to-task-dialog', () => ({
  AddFindingsToTaskDialog: () => null,
}))
vi.mock('@/features/findings', async (orig) => ({
  ...(await orig<typeof import('@/features/findings')>()),
  FindingDetailDrawer: () => null,
  CreateFindingDialog: () => null,
}))

vi.mock('@/features/assets/hooks/use-assets', () => ({
  useAsset: () => ({ asset: null, isLoading: false, error: undefined }),
}))

import FindingsPage from '../page'
import { ApiClientError } from '@/lib/api/error-handler'

Element.prototype.scrollIntoView ??= () => {}

beforeEach(() => {
  perms.exportAllowed = true
  listTotal.value = 25000
  exportCalls.length = 0
  exportResult.value = { filename: 'f.csv', maxRows: 10000 }
  toasts.success.mockClear()
  toasts.warning.mockClear()
  toasts.error.mockClear()
  window.history.replaceState(null, '', '/findings?sort=-severity')
})

async function exportCsv() {
  render(<FindingsPage />)
  await userEvent.click(screen.getAllByRole('button', { name: 'Export' })[0])
  await userEvent.click(await screen.findByRole('menuitem', { name: 'Export as CSV' }))
}

describe('Findings export', () => {
  it('offers no export without findings:export (no page-only fallback)', () => {
    perms.exportAllowed = false
    render(<FindingsPage />)
    expect(screen.queryByRole('button', { name: 'Export' })).toBeNull()
    expect(screen.queryByRole('menuitem', { name: 'Export as CSV' })).toBeNull()
  })

  it('exports on the server with the list filter and sort, never one page', async () => {
    listTotal.value = 50
    await exportCsv()
    await waitFor(() => expect(exportCalls).toHaveLength(1))
    expect(exportCalls[0].format).toBe('csv')
    expect(exportCalls[0].path).toMatch(/^\/api\/v1\/findings\/export\?/)
    expect(exportCalls[0].path).toContain('sort=-severity')
    expect(exportCalls[0].path).toContain('format=csv')
    expect(exportCalls[0].path).not.toMatch(/[?&](page|per_page)=/)
    await waitFor(() => expect(toasts.success).toHaveBeenCalled())
    expect(toasts.warning).not.toHaveBeenCalled()
  })

  it('says when the list holds more findings than the export cap', async () => {
    await exportCsv()
    await waitFor(() => expect(toasts.warning).toHaveBeenCalled())
    expect(String(toasts.warning.mock.calls[0][0])).toContain('10,000')
    expect(String(toasts.warning.mock.calls[0][0])).toContain('25,000')
  })

  it('explains a refused export', async () => {
    exportResult.value = new ApiClientError('forbidden', 'FORBIDDEN', 403, {
      missing_permissions: ['findings:export'],
    })
    await exportCsv()
    await waitFor(() => expect(toasts.error).toHaveBeenCalled())
    expect(toasts.error.mock.calls[0][0]).toBe('You cannot export findings')
    expect(String(toasts.error.mock.calls[0][1]?.description)).toMatch(/findings:export|Export/i)
  })

  it('says an export is already running on a 429', async () => {
    exportResult.value = new ApiClientError('busy', 'TOO_MANY_REQUESTS', 429)
    await exportCsv()
    await waitFor(() => expect(toasts.error).toHaveBeenCalled())
    expect(toasts.error.mock.calls[0][0]).toBe('An export of yours is still running')
  })
})
