import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import { I18nProvider } from '@/context/i18n-provider'
import WorkflowsPage from '../page'

const state = vi.hoisted(() => ({ items: [] as unknown[] }))

vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/features/workflows/components/automation-canvas', () => ({
  AutomationCanvas: () => null,
}))
vi.mock('@/hooks/use-url-param', () => ({
  useUrlFilter: (_k: string, fallback: string) => [fallback, vi.fn()],
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}))
vi.mock('@/lib/api/workflow-hooks', () => ({
  useWorkflows: () => ({
    data: { items: state.items, total: state.items.length },
    isLoading: false,
    error: undefined,
  }),
  useWorkflowRuns: () => ({ data: { items: [], total: 0 }, isLoading: false }),
  useTriggerWorkflow: () => ({ trigger: vi.fn(), isMutating: false }),
  useCreateWorkflow: () => ({ trigger: vi.fn(), isMutating: false }),
  useDeleteWorkflow: () => ({ trigger: vi.fn(), isMutating: false }),
  invalidateWorkflowsCache: vi.fn(),
  invalidateWorkflowRunsCache: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

// English literals the page used to hard-code.
const FORMER_ENGLISH = [
  'New workflow',
  'Recent executions',
  'Visual builder',
  'No workflows yet',
  'Create your first automation workflow.',
  'Success rate',
  'Total runs',
  'Search workflows...',
]

describe('Automations page i18n', () => {
  it('renders the empty page in Vietnamese', () => {
    state.items = []
    const { container } = render(
      <I18nProvider locale="vi">
        <WorkflowsPage />
      </I18nProvider>
    )
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Tự động hóa')
    expect(screen.getByRole('button', { name: /Quy trình mới/ })).toBeInTheDocument()
    expect(screen.getByText('Chưa có quy trình nào')).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Lần chạy gần đây' })).toBeInTheDocument()
    for (const en of FORMER_ENGLISH) expect(container.textContent).not.toContain(en)
  })

  it('translates the trigger and status of a listed workflow', () => {
    state.items = [
      {
        id: 'w1',
        tenant_id: 't1',
        name: 'Escalate criticals',
        is_active: true,
        total_runs: 4,
        successful_runs: 2,
        failed_runs: 2,
        nodes: [
          {
            node_key: 't1',
            node_type: 'trigger',
            name: 'Trigger',
            config: { trigger_type: 'finding_created' },
          },
        ],
        created_at: '2026-10-01T00:00:00Z',
        updated_at: '2026-10-01T00:00:00Z',
      },
    ]
    const { container } = render(
      <I18nProvider locale="vi">
        <WorkflowsPage />
      </I18nProvider>
    )
    expect(screen.getByText('Phát hiện được tạo')).toBeInTheDocument()
    expect(container.textContent).toContain('thành công 50%')
    expect(container.textContent).not.toContain('Finding Created')
    expect(container.textContent).not.toContain('success)')
  })

  it('keeps English text out of the JSX of the page, canvas and inspector', () => {
    const root = join(__dirname, '../../../../../')
    const files = [
      'app/(dashboard)/(mobilization)/automations/page.tsx',
      'features/workflows/components/automation-canvas.tsx',
      'features/workflows/components/automation-inspector.tsx',
    ]
    for (const f of files) {
      const src = readFileSync(join(root, f), 'utf8')
      // Text between a closing and an opening angle bracket that starts like a word.
      const literals = [...src.matchAll(/>\s*([A-Z][a-z][^<>{}]*)</g)].map((m) => m[1].trim())
      expect(literals, f).toEqual([])
      expect(src, f).not.toMatch(/\b(?:title|placeholder|aria-label|label|description)="[A-Z]/)
    }
  })
})
