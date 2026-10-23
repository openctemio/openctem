import { Suspense } from 'react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { get, post } from '@/lib/api/client'

import WorkflowBuilderPage from '../page'

// The workflow builder page: a failed load is not "not found" and can be
// retried, "no draft" (404) is not an error, and a system template offers
// the Clone its subtitle promises.
const push = vi.fn()
const canWrite = vi.hoisted(() => ({ value: true }))

vi.mock('next/navigation', () => ({ useRouter: () => ({ push }) }))
vi.mock('next/dynamic', () => ({ default: () => () => <div data-testid="canvas" /> }))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
  useBreadcrumbTitle: () => undefined,
}))
vi.mock('@/lib/api/client', () => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/tool-hooks', () => ({ useToolsWithConfig: () => ({ data: undefined }) }))
vi.mock('@/features/scan-workflows/lib/use-capability-table', () => ({
  useCapabilityTable: () => ({ table: [] }),
}))
vi.mock('@/features/scan-workflows/components/node-palette', () => ({ NodePalette: () => null }))
vi.mock('@/features/scan-workflows/components/node-inspector', () => ({
  NodeInspector: () => null,
}))
vi.mock('@/features/scan-workflows/components/template-update-card', () => ({
  TemplateUpdateCard: () => null,
}))
vi.mock('@/features/scan-workflows/components/draft-issues-panel', () => ({
  DraftIssuesPanel: () => null,
}))
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  useHasPermission: () => canWrite.value,
}))

const workflow = (over: Record<string, unknown> = {}) => ({
  id: 'w1',
  name: 'Full recon',
  version: 3,
  steps: [],
  is_system_template: false,
  ...over,
})

function mockApi(wf: unknown, draft: unknown) {
  vi.mocked(get).mockImplementation(async (url: string) => {
    if (url.endsWith('/draft')) {
      if (draft instanceof Error) throw draft
      return draft
    }
    if (wf instanceof Error) throw wf
    return wf
  })
}

const err = (statusCode: number) => Object.assign(new Error('boom'), { statusCode })

// A promise React reads synchronously (use() does not suspend on it).
const resolved = <T,>(value: T) =>
  Object.assign(Promise.resolve(value), { status: 'fulfilled' as const, value })

async function open() {
  render(
    <Suspense fallback={null}>
      <WorkflowBuilderPage params={resolved({ id: 'w1' })} />
    </Suspense>
  )
}

describe('Workflow builder page', () => {
  beforeEach(() => {
    vi.mocked(get).mockReset()
    vi.mocked(post).mockReset()
    push.mockClear()
    canWrite.value = true
  })

  it('says not found on a 404', async () => {
    mockApi(err(404), null)
    await open()
    expect(await screen.findByText('Workflow not found')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull()
  })

  it('shows a retryable error on a server failure and loads again on Retry', async () => {
    mockApi(err(500), null)
    await open()
    const retry = await screen.findByRole('button', { name: 'Retry' })
    expect(screen.queryByText('Workflow not found')).toBeNull()
    const before = vi.mocked(get).mock.calls.length
    await userEvent.click(retry)
    await waitFor(() => expect(vi.mocked(get).mock.calls.length).toBeGreaterThan(before))
  })

  it('treats a missing draft (404) as no draft, not an error', async () => {
    mockApi(workflow(), err(404))
    await open()
    expect(await screen.findByRole('heading', { name: 'Full recon' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Back to workflows' })).toBeInTheDocument()
  })

  it('does not hide a failed draft load as "no draft"', async () => {
    mockApi(workflow(), err(500))
    await open()
    expect(await screen.findByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })

  it('clones a system template and opens the copy', async () => {
    mockApi(workflow({ is_system_template: true }), null)
    vi.mocked(post).mockResolvedValue({ id: 'w2' })
    await open()
    await userEvent.click(await screen.findByRole('button', { name: 'Clone' }))
    expect(vi.mocked(post).mock.calls[0][0]).toMatch(/w1\/clone/)
    await waitFor(() => expect(push).toHaveBeenCalledWith('/scans/workflows/w2'))
  })

  it('offers no Clone without scan workflow write access', async () => {
    canWrite.value = false
    mockApi(workflow({ is_system_template: true }), null)
    await open()
    await screen.findByRole('heading', { name: 'Full recon' })
    expect(screen.queryByRole('button', { name: 'Clone' })).toBeNull()
  })
})
