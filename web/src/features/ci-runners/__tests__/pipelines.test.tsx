import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { CIPipelinesPanel } from '../components/ci-pipelines-panel'
import { resolveLegacyRoute } from '@/config/legacy-routes'
import {
  PIPELINE_STATUSES,
  PIPELINE_STATUS_META,
  cadenceLabel,
  pipelinesURL,
  repositoryPath,
  workflowFile,
} from '../lib/pipeline'

// ── mocks ──────────────────────────────────────────────────

let pipelines: unknown[] = []
let counts: Record<string, number> = {}
let lastPipelineFilters: Record<string, unknown> | undefined

vi.mock('../api/use-ci', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../api/use-ci')>()),
  useCIPipelines: (f: Record<string, unknown>) => {
    lastPipelineFilters = f
    return {
      data: { data: pipelines, counts, total: pipelines.length, total_pages: 1 },
      isLoading: false,
      mutate: vi.fn(),
    }
  },
  useCIPipeline: () => ({ data: undefined }),
  useCIRuns: () => ({ data: { data: [], total_pages: 1 }, isLoading: false, mutate: vi.fn() }),
  useCIRun: () => ({ data: undefined }),
}))

let perms: string[] = []
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: (p: string) => perms.includes(p), isLoading: false }),
}))

vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't-123', slug: 'acme', role: 'owner' } }),
}))

vi.mock('next/link', () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}))

const stale = {
  id: 'p1',
  mode: 'runner',
  kind: 'ci_pipeline',
  role: 'scanner',
  provider: 'github',
  repository: 'github.com/acme/api',
  workflow_path: '.github/workflows/scan.yml',
  workflow_name: 'Security scan',
  status: 'stale',
  freshness: 'stale',
  gate: 'passing',
  health: 'ok',
  inactive: false,
  last_run_at: '2026-09-01T10:00:00Z',
  sensor_version: 'v0.9.0',
  version_status: 'latest',
}

const failing = {
  ...stale,
  id: 'p2',
  repository: 'github.com/acme/web',
  status: 'failing',
  gate: 'failing',
}

// ── lib ──────────────────────────────────────────────────

describe('pipeline lib', () => {
  it('never labels a pipeline offline, and only a failing gate is red', () => {
    for (const s of PIPELINE_STATUSES) {
      expect(PIPELINE_STATUS_META[s].label.toLowerCase()).not.toContain('offline')
      if (s !== 'failing') expect(PIPELINE_STATUS_META[s].tone).not.toBe('destructive')
    }
    expect(PIPELINE_STATUS_META.failing.tone).toBe('destructive')
    expect(PIPELINE_STATUS_META.stale.tone).toBe('warning')
  })

  it('builds the list URLs', () => {
    expect(
      pipelinesURL('/api/v1/ci', {
        status: ['failing', 'stale'],
        includeInactive: true,
        search: 'api',
      })
    ).toBe(
      '/api/v1/ci/pipelines?status=failing%2Cstale&include_inactive=true&search=api&page=1&per_page=25'
    )
  })

  it('formats names and cadence', () => {
    expect(repositoryPath('github.com/acme/api')).toBe('acme/api')
    expect(repositoryPath('acme/api')).toBe('acme/api')
    expect(workflowFile('.github/workflows/scan.yml')).toBe('scan.yml')
    expect(cadenceLabel(2 * 86400)).toBe('every 2 days')
    expect(cadenceLabel(6 * 3600)).toBe('every 6 hours')
    expect(cadenceLabel(0)).toBeNull()
  })

  it('sends the old CI runners and runner-sensor links to CI/CD integration', () => {
    expect(resolveLegacyRoute('/ci-runners')).toBe('/ci-cd')
    expect(resolveLegacyRoute('/runners')).toBe('/ci-cd')
    expect(resolveLegacyRoute('/ci-runners/0192-run')).toBe('/ci-cd?view=runs&run=0192-run')
  })

  it('sends the retired Runner mode of Sensors to CI/CD, keeping the open pipeline', () => {
    expect(resolveLegacyRoute('/sensors?mode=runner&pipeline=p1')).toBe(
      '/ci-cd?mode=runner&pipeline=p1'
    )
    // Sensors itself, and its other old modes, stay on Sensors.
    expect(resolveLegacyRoute('/sensors')).toBeNull()
    expect(resolveLegacyRoute('/sensors?mode=all')).toBeNull()
    expect(resolveLegacyRoute('/sensors?mode=daemon')).toBeNull()
    expect(resolveLegacyRoute('/sensors?mode=collector')).toBeNull()
  })
})

// ── pipelines panel ──────────────────────────────────────────

describe('CIPipelinesPanel', () => {
  beforeEach(() => {
    window.history.replaceState(null, '', '/ci-cd')
    pipelines = []
    counts = {}
    lastPipelineFilters = undefined
  })

  it('offers to connect a pipeline when there is none', () => {
    perms = ['scans:ci:write']
    render(<CIPipelinesPanel />)
    expect(screen.getByText('No CI pipelines yet')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /connect a pipeline/i })).toBeInTheDocument()
    // One way to start: the wizard (its advanced settings stay on the Trust tab).
    expect(screen.queryByRole('link', { name: /set up ci trust/i })).not.toBeInTheDocument()
    perms = []
  })

  it('tells readers to ask an administrator when there is no pipeline', () => {
    perms = []
    render(<CIPipelinesPanel />)
    expect(screen.queryByRole('button', { name: /connect a pipeline/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /set up ci trust/i })).not.toBeInTheDocument()
    expect(screen.getByText(/ask an administrator/i)).toBeInTheDocument()
  })

  it('lists pipelines with their status and never shows offline', () => {
    pipelines = [failing, stale]
    counts = { failing: 1, stale: 1, fresh: 3, archived: 2 }
    render(<CIPipelinesPanel />)
    expect(screen.getAllByText('acme/api').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Stale').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Failing').length).toBeGreaterThan(0)
    expect(screen.queryByText(/offline/i)).not.toBeInTheDocument()
    // Header counts: 5 active (archived is inactive), 2 inactive.
    const strip = screen.getByText('CI pipelines').closest('dl') as HTMLElement
    expect(within(strip).getByText('5')).toBeInTheDocument()
    expect(within(strip).getByText('Inactive')).toBeInTheDocument()
    // Inactive pipelines are hidden by default.
    expect(lastPipelineFilters?.includeInactive).toBe(false)
  })

  it('shows inactive pipelines on request and filters by a quick metric', async () => {
    pipelines = [failing]
    counts = { failing: 1 }
    render(<CIPipelinesPanel />)
    await userEvent.click(screen.getByRole('switch', { name: 'Show inactive' }))
    expect(lastPipelineFilters?.includeInactive).toBe(true)
    await userEvent.click(screen.getByRole('button', { name: /failing gate/i }))
    expect(lastPipelineFilters?.status).toEqual(['failing'])
  })

  it('lists only repositories with their own gate settings under Has overrides', async () => {
    pipelines = [failing]
    counts = { failing: 1 }
    render(<CIPipelinesPanel />)
    expect(lastPipelineFilters?.hasPolicyOverride).toBe(false)
    await userEvent.click(screen.getByRole('switch', { name: 'Has overrides' }))
    expect(lastPipelineFilters?.hasPolicyOverride).toBe(true)
    expect(window.location.search).toContain('overrides=1')
  })

  it('keeps the filter when no repository overrides the gate', () => {
    window.history.replaceState(null, '', '/ci-cd?overrides=1')
    render(<CIPipelinesPanel />)
    expect(lastPipelineFilters?.hasPolicyOverride).toBe(true)
    expect(screen.getByRole('switch', { name: 'Has overrides' })).toBeChecked()
  })
})
