import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import WorkflowsPage from '../page'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

// The workflows list is read whole and searched, sorted and paged on the page.
const listCalls: Array<Record<string, unknown> | undefined> = []
let response: unknown
let readError: unknown
let canWrite = true
const invalidate = vi.hoisted(() => vi.fn())
const postMock = vi.hoisted(() => vi.fn())

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => '/scans/workflows',
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/features/scans/components/scans-section-tabs', () => ({
  ScansPageHeader: ({ children }: { children?: React.ReactNode }) => <header>{children}</header>,
  ScansSectionTabs: () => null,
}))
vi.mock('@/features/scan-workflows/components/workflow-form', () => ({
  ScanWorkflowForm: () => null,
}))
vi.mock('@/lib/permissions', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
    useHasPermission: () => canWrite,
  }
})
vi.mock('@/lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/api')>()),
  useScanWorkflows: (filters?: Record<string, unknown>) => {
    listCalls.push(filters)
    return { data: response, isLoading: false, isValidating: false, error: readError }
  },
  useCreateScanWorkflow: () => ({ trigger: vi.fn(), isMutating: false }),
  invalidateAllScanWorkflowCaches: invalidate,
  post: postMock,
  get: vi.fn(),
  put: vi.fn(),
}))

const urlState = new Proxy({} as Record<string, string | undefined>, {
  get: (_, key) => new URLSearchParams(window.location.search).get(String(key)) ?? undefined,
  set: (_, key, value) => {
    const params = new URLSearchParams(window.location.search)
    params.set(String(key), String(value))
    window.history.replaceState(null, '', `/scans/workflows?${params}`)
    return true
  },
})

const workflow = (over: Record<string, unknown>) => ({
  id: 'w1',
  tenant_id: 't',
  name: 'Web recon',
  description: 'Finds hosts, then checks them',
  is_active: true,
  is_system_template: false,
  is_retired: false,
  version: 3,
  steps: [{}, {}],
  settings: {},
  tags: [],
  ...over,
})

const rowNames = () =>
  within(screen.getByRole('table'))
    .getAllByRole('row')
    .slice(1)
    .map((r) => r.querySelector('[data-slot="workflow-name-cell"] span')?.textContent)

describe('/scans/workflows list', () => {
  beforeEach(() => {
    listCalls.length = 0
    readError = undefined
    canWrite = true
    invalidate.mockClear()
    postMock.mockReset()
    window.history.replaceState(null, '', '/scans/workflows')
    response = {
      data: [
        workflow({}),
        workflow({ id: 'w2', name: 'API checks', is_active: false, version: 1, steps: [{}] }),
        workflow({ id: 's1', name: 'Full perimeter', is_system_template: true, version: 7 }),
      ],
      total: 3,
      page: 1,
      per_page: 100,
    }
  })

  it('names the view, says the count once and opens by name, A to Z', () => {
    render(<WorkflowsPage />)
    expect(screen.getByRole('heading', { name: 'All workflows' })).toBeInTheDocument()
    const counts = document.querySelectorAll('[data-slot="list-count"]')
    expect(counts).toHaveLength(1)
    expect(counts[0]).toHaveTextContent('3 workflows')
    expect(rowNames()).toEqual(['API checks', 'Full perimeter', 'Web recon'])
    const sorted = within(screen.getByRole('table'))
      .getAllByRole('columnheader')
      .filter((h) => h.getAttribute('aria-sort'))
    expect(sorted).toHaveLength(1)
    expect(sorted[0]).toHaveTextContent('Workflow')
    expect(sorted[0]).toHaveAttribute('aria-sort', 'ascending')
  })

  it('gives every column a header word and keeps a row on one line', () => {
    render(<WorkflowsPage />)
    const table = screen.getByRole('table')
    expect(
      within(table)
        .getAllByRole('columnheader')
        .map((h) => h.textContent?.trim())
        .filter(Boolean)
    ).toEqual(['Workflow', 'Status', 'Steps', 'Version', 'Enabled', 'Actions'])
    // The description is the name's hover text, not a second line.
    expect(within(table).queryByText('Finds hosts, then checks them')).toBeNull()
    expect(within(table).getByText('Web recon')).toHaveAttribute(
      'title',
      'Web recon\nFinds hosts, then checks them'
    )
    // No bulk action on workflows: no checkbox column.
    expect(within(table).queryByRole('checkbox')).toBeNull()
  })

  it('sorts from a header and keeps the sort in the URL', async () => {
    render(<WorkflowsPage />)
    await userEvent.click(screen.getByRole('button', { name: /^Version/ }))
    expect(urlState.sort).toBe('-version')
    expect(rowNames()).toEqual(['Full perimeter', 'Web recon', 'API checks'])
  })

  it('narrows by owner from the toolbar select and names the view after it', async () => {
    const user = userEvent.setup()
    render(<WorkflowsPage />)
    await user.click(screen.getByRole('button', { name: /^Owner/ }))
    await user.click(await screen.findByRole('menuitemradio', { name: 'System templates' }))
    expect(urlState.owner).toBe('system')
    expect(rowNames()).toEqual(['Full perimeter'])
    expect(screen.getByRole('heading', { name: 'System templates' })).toBeInTheDocument()
    expect(document.querySelector('[data-slot="list-count"]')).toHaveTextContent('1 workflow')
  })

  it('searches by name on the page and keeps the text in the URL', async () => {
    urlState.q = 'api'
    render(<WorkflowsPage />)
    expect(rowNames()).toEqual(['API checks'])
    expect(screen.getByRole('searchbox')).toHaveValue('api')
  })

  it('shows retired workflows from Add filter, as a chip that clears on its own', async () => {
    const user = userEvent.setup()
    render(<WorkflowsPage />)
    expect(listCalls.at(-1)).toMatchObject({ include_retired: false })
    await user.click(screen.getByRole('button', { name: /add filter/i }))
    await user.click(await screen.findByRole('checkbox', { name: 'Show retired' }))
    expect(urlState.retired).toBe('show')
    expect(listCalls.at(-1)).toMatchObject({ include_retired: true })
    await user.keyboard('{Escape}')
    const chips = screen.getByTestId('workflows-filter-chips')
    await user.click(
      within(chips).getByRole('button', { name: 'Remove filter Retired workflows shown' })
    )
    expect(urlState.retired).toBeUndefined()
    expect(screen.queryByTestId('workflows-filter-chips')).toBeNull()
  })

  it('keeps the row menu set and order of a workflow of the organization', async () => {
    render(<WorkflowsPage />)
    await userEvent.click(
      screen.getByRole('button', { name: 'Actions for Web recon', hidden: true })
    )
    expect((await screen.findAllByRole('menuitem')).map((i) => i.textContent)).toEqual([
      'View details',
      'Edit workflow',
      'Open editor',
      'Clone',
    ])
  })

  it('offers Use template on a system template, and nothing that edits it', async () => {
    render(<WorkflowsPage />)
    await userEvent.click(
      screen.getByRole('button', { name: 'Actions for Full perimeter', hidden: true })
    )
    expect((await screen.findAllByRole('menuitem')).map((i) => i.textContent)).toEqual([
      'View details',
      'Use template',
    ])
  })

  it('hides every change without the write permission', async () => {
    canWrite = false
    render(<WorkflowsPage />)
    // The switch stays visible, disabled, and names its workflow.
    expect(screen.getByRole('switch', { name: 'Deactivate workflow Web recon' })).toBeDisabled()
    // One action left: the shared menu draws it as the row's one button.
    expect(screen.queryByRole('button', { name: 'Actions for Web recon', hidden: true })).toBeNull()
    expect(screen.getAllByRole('button', { name: /View details/, hidden: true })).toHaveLength(3)
  })

  it('turns a workflow off from its switch, as before', async () => {
    postMock.mockResolvedValue({})
    render(<WorkflowsPage />)
    await userEvent.click(screen.getByRole('switch', { name: 'Deactivate workflow Web recon' }))
    expect(String(postMock.mock.calls[0]?.[0])).toContain('/w1/deactivate')
  })

  it('tells an empty organization from a list with no match', async () => {
    response = { data: [], total: 0, page: 1, per_page: 100 }
    const { unmount } = render(<WorkflowsPage />)
    expect(screen.getByText('No workflows yet')).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: /workflow/i }).length).toBeGreaterThan(0)
    unmount()
    urlState.owner = 'mine'
    response = { data: [workflow({ id: 's1', is_system_template: true })], total: 1 }
    render(<WorkflowsPage />)
    expect(screen.getByText('No custom workflows yet')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(window.location.search).toBe('')
  })

  it('shows the no-access notice when the server refuses the read', () => {
    response = undefined
    readError = { statusCode: 403, code: 'FORBIDDEN' }
    render(<WorkflowsPage />)
    expect(screen.getByText('You do not have access to the workflows list')).toBeInTheDocument()
    expect(screen.queryByRole('table')).toBeNull()
  })

  it('refreshes from the title row', async () => {
    render(<WorkflowsPage />)
    await userEvent.click(screen.getByRole('button', { name: 'Refresh' }))
    expect(invalidate).toHaveBeenCalled()
  })
})
