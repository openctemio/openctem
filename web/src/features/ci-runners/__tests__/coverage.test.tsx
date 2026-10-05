import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { CIPipelinesPanel } from '../components/ci-pipelines-panel'
import { RetirePipelineDialog } from '../components/ci-pipeline-sheet'
import { coverageURL, validRetireReason } from '../lib/coverage'
import { INACTIVE_PIPELINE_STATUSES, PIPELINE_STATUS_META } from '../lib/pipeline'

// ── mocks ──────────────────────────────────────────────────

let coverage: unknown = undefined
let lastCoverageFilters: Record<string, unknown> | undefined
let perms: string[] = []
const mockExpect = vi.fn(async () => ({}))
const mockRetire = vi.fn(async () => ({ findings_closed: 2 }))

vi.mock('../api/use-ci', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../api/use-ci')>()),
  useCIPipelines: () => ({
    data: { data: [], counts: {}, total: 0, total_pages: 1 },
    isLoading: false,
    mutate: vi.fn(),
  }),
  useCIPipeline: () => ({ data: undefined, mutate: vi.fn() }),
  useCIRuns: () => ({ data: { data: [], total_pages: 1 }, isLoading: false, mutate: vi.fn() }),
  useCIRun: () => ({ data: undefined }),
  useCICoverage: (f: Record<string, unknown>) => {
    lastCoverageFilters = f
    return { data: coverage, isLoading: false, mutate: vi.fn() }
  },
  useSetCoverageExpectation: () => ({ trigger: mockExpect, isMutating: false }),
  useRetirePipeline: () => ({ trigger: mockRetire, isMutating: false }),
}))

vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't-123', slug: 'acme', role: 'owner' } }),
}))

vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: (p: string) => perms.includes(p), isLoading: false }),
}))

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

vi.mock('next/link', () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}))

const gapRepo = {
  repository_asset_id: 'a1',
  repository: 'github.com/acme/api',
  criticality: 'critical',
  covered: true,
  gap: true,
  expected: true,
  expected_capabilities: ['sast', 'secrets'],
  pipelines: 1,
  capabilities: [
    {
      capability: 'sast',
      state: 'fresh',
      expected: true,
      source_kind: 'ci_pipeline',
      source_name: '.github/workflows/scan.yml',
      last_at: '2026-10-04T10:00:00Z',
    },
    { capability: 'sca', state: 'stale', expected: false },
    { capability: 'secrets', state: 'never', expected: true },
    { capability: 'iac', state: 'never', expected: false },
  ],
}

const uncoveredRepo = {
  repository_asset_id: 'a2',
  repository: 'github.com/acme/legacy',
  criticality: 'low',
  covered: false,
  gap: false,
  expected: false,
  expected_capabilities: [],
  pipelines: 0,
  capabilities: ['sast', 'sca', 'secrets', 'iac'].map((c) => ({
    capability: c,
    state: 'never',
    expected: false,
  })),
}

function setCoverage(rows: unknown[]) {
  coverage = {
    data: rows,
    total: rows.length,
    total_pages: 1,
    summary: {
      repositories: 2,
      covered: 1,
      uncovered: 1,
      expected: 1,
      gaps: 1,
      uncovered_by_criticality: { low: 1 },
      fresh_by_capability: { sast: 1, sca: 0, secrets: 0, iac: 0 },
    },
    templates: [
      {
        template: 'acme/.github/.github/workflows/scan.yml',
        current: 'refs/tags/v2',
        drifted: 1,
        total: 3,
        versions: [],
      },
    ],
    truncated: false,
  }
}

// ── lib ──────────────────────────────────────────────────

describe('coverage lib', () => {
  it('builds the coverage URL', () => {
    expect(coverageURL('/api/v1/ci', { filter: 'gap', search: 'api', page: 2, perPage: 10 })).toBe(
      '/api/v1/ci/coverage?filter=gap&search=api&page=2&per_page=10'
    )
    expect(coverageURL('/api/v1/ci')).toBe('/api/v1/ci/coverage?page=1&per_page=25')
  })

  it('requires a retirement reason of 10 to 2,000 characters', () => {
    expect(validRetireReason('short')).toBe(false)
    expect(validRetireReason('          x         ')).toBe(false)
    expect(validRetireReason('the workflow was removed')).toBe(true)
    expect(validRetireReason('x'.repeat(2001))).toBe(false)
  })

  it('treats a retired pipeline as inactive and never as offline', () => {
    expect(INACTIVE_PIPELINE_STATUSES).toContain('retired')
    expect(PIPELINE_STATUS_META.retired.tone).toBe('muted')
    expect(PIPELINE_STATUS_META.retired.label.toLowerCase()).not.toContain('offline')
  })
})

// ── coverage view ────────────────────────────────────────

describe('Coverage view', () => {
  beforeEach(() => {
    window.history.replaceState(null, '', '/sensors?mode=runner&view=coverage')
    perms = []
    lastCoverageFilters = undefined
    mockExpect.mockClear()
    setCoverage([gapRepo, uncoveredRepo])
  })

  it('opens from the alert link and shows each capability, an expected one that is not fresh as a gap', () => {
    render(<CIPipelinesPanel />)
    const row = screen.getByText('acme/api').closest('tr') as HTMLElement
    expect(within(row).getByText('Fresh')).toBeInTheDocument()
    expect(within(row).getByText('Stale')).toBeInTheDocument()
    expect(within(row).getByText('Never · expected')).toBeInTheDocument()
    expect(row.querySelector('[data-state="gap"]')).not.toBeNull()
    expect(screen.getByText('Template drift')).toBeInTheDocument()
    expect(screen.getByText(/1 of 3 pipelines not on refs\/tags\/v2/)).toBeInTheDocument()
  })

  it('filters by a summary metric', async () => {
    render(<CIPipelinesPanel />)
    await userEvent.click(screen.getByRole('button', { name: /gaps/i }))
    expect(lastCoverageFilters?.filter).toBe('gap')
    await userEvent.click(screen.getByRole('button', { name: /not looked at/i }))
    expect(lastCoverageFilters?.filter).toBe('uncovered')
  })

  it('lets only CI writers mark a repository as expected', async () => {
    const { unmount } = render(<CIPipelinesPanel />)
    expect(screen.queryByRole('button', { name: /expect coverage of/i })).not.toBeInTheDocument()
    unmount()

    perms = ['scans:ci:write']
    render(<CIPipelinesPanel />)
    await userEvent.click(
      screen.getByRole('button', { name: 'Expect coverage of github.com/acme/legacy' })
    )
    expect(mockExpect).toHaveBeenCalledWith({ assetId: 'a2', expected: true })
    await userEvent.click(
      screen.getByRole('button', { name: 'Stop expecting coverage of github.com/acme/api' })
    )
    expect(mockExpect).toHaveBeenCalledWith({ assetId: 'a1', expected: false })
  })

  it('explains an empty scope', () => {
    coverage = {
      data: [],
      total: 0,
      total_pages: 1,
      summary: { repositories: 0, covered: 0, uncovered: 0, expected: 0, gaps: 0 },
      templates: [],
    }
    render(<CIPipelinesPanel />)
    expect(screen.getByText('No repositories in scope')).toBeInTheDocument()
  })
})

// ── retire ───────────────────────────────────────────────

describe('RetirePipelineDialog', () => {
  beforeEach(() => mockRetire.mockClear())

  it('needs a reason, then retires with it', async () => {
    const onRetired = vi.fn()
    render(
      <RetirePipelineDialog
        pipelineId="p1"
        label="github.com/acme/api scan.yml"
        open
        onOpenChange={vi.fn()}
        onRetired={onRetired}
      />
    )
    const confirm = screen.getByRole('button', { name: 'Retire pipeline' })
    expect(confirm).toBeDisabled()
    await userEvent.type(screen.getByLabelText(/reason/i), 'too short')
    expect(confirm).toBeDisabled()
    await userEvent.type(screen.getByLabelText(/reason/i), ' and now long enough')
    expect(confirm).toBeEnabled()
    await userEvent.click(confirm)
    expect(mockRetire).toHaveBeenCalledWith({
      id: 'p1',
      reason: 'too short and now long enough',
    })
    expect(onRetired).toHaveBeenCalled()
  })
})
