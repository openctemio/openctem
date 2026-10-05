import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { CIPipelinesPanel } from '../components/ci-pipelines-panel'
import { FleetAllView } from '@/features/sensors/components/fleet-all-view'
import { fleetPageMode } from '@/features/sensors/components/sensors-section'
import { resolveLegacyRoute } from '@/config/legacy-routes'
import {
  PIPELINE_STATUSES,
  PIPELINE_STATUS_META,
  cadenceLabel,
  fleetURL,
  pipelinesURL,
  repositoryPath,
  workflowFile,
} from '../lib/pipeline'

// ── mocks ──────────────────────────────────────────────────

let pipelines: unknown[] = []
let counts: Record<string, number> = {}
let lastPipelineFilters: Record<string, unknown> | undefined
let fleet: unknown = undefined

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
  useFleet: () => ({ data: fleet, isLoading: false, mutate: vi.fn() }),
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
    expect(fleetURL({ mode: 'runner', attention: true, page: 2, perPage: 10 })).toBe(
      '/api/v1/fleet?mode=runner&attention=true&page=2&per_page=10'
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

  it('reads the page mode from the URL, legacy run-style links included', () => {
    // The page opens on the daemons; CI pipelines have their own page.
    expect(fleetPageMode('', true, true)).toBe('daemon')
    expect(fleetPageMode('all', true, true)).toBe('all')
    expect(fleetPageMode('', true, false)).toBe('daemon')
    expect(fleetPageMode('', false, true)).toBe('runner')
    expect(fleetPageMode('runner', true, true)).toBe('runner')
    // A mode the caller may not read falls back.
    expect(fleetPageMode('runner', true, false)).toBe('daemon')
    expect(fleetPageMode('all', true, false)).toBe('daemon')
    // ?mode=ci|standalone|collector were the old facet and tab.
    expect(fleetPageMode('ci', true, true)).toBe('daemon')
    expect(fleetPageMode('collector', true, true)).toBe('daemon')
  })

  it('sends the old CI runners and runner-sensor links to CI/CD integration', () => {
    expect(resolveLegacyRoute('/ci-runners')).toBe('/ci-cd')
    expect(resolveLegacyRoute('/runners')).toBe('/ci-cd')
    expect(resolveLegacyRoute('/ci-runners/0192-run')).toBe('/ci-cd?view=runs&run=0192-run')
  })
})

// ── runner mode ──────────────────────────────────────────

describe('CIPipelinesPanel', () => {
  beforeEach(() => {
    window.history.replaceState(null, '', '/sensors?mode=runner')
    pipelines = []
    counts = {}
    lastPipelineFilters = undefined
  })

  it('explains how to connect a pipeline when there is none', () => {
    render(<CIPipelinesPanel />)
    expect(screen.getByText('No CI pipelines yet')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /set up ci trust/i })).toHaveAttribute(
      'href',
      '/ci-cd?tab=setup'
    )
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
    await userEvent.click(screen.getByRole('switch'))
    expect(lastPipelineFilters?.includeInactive).toBe(true)
    await userEvent.click(screen.getByRole('button', { name: /failing gate/i }))
    expect(lastPipelineFilters?.status).toEqual(['failing'])
  })
})

// ── all mode ─────────────────────────────────────────────

describe('FleetAllView', () => {
  beforeEach(() => {
    window.history.replaceState(null, '', '/sensors')
    fleet = {
      data: [
        {
          id: 'd1',
          mode: 'daemon',
          kind: 'sensor',
          role: 'scanner',
          name: 'edge-1',
          status: 'offline',
          attention: true,
        },
        { ...stale, name: 'github.com/acme/api · Security scan' },
      ],
      total: 2,
      total_pages: 1,
      modes: ['daemon', 'runner'],
      counts: {
        daemon: { total: 1, attention: 1, inactive: 0, by_status: { offline: 1 } },
        runner: {
          total: 4,
          attention: 1,
          inactive: 1,
          by_status: { stale: 1, fresh: 2, archived: 1 },
        },
      },
    }
  })

  it('lists daemons and CI pipelines, each with its own status vocabulary', async () => {
    const onOpenRunner = vi.fn()
    const onOpenDaemon = vi.fn()
    render(<FleetAllView onOpenDaemon={onOpenDaemon} onOpenRunner={onOpenRunner} />)
    expect(screen.getAllByText('Runner').length).toBeGreaterThan(0)
    expect(screen.getAllByText('· CI pipeline').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Daemon').length).toBeGreaterThan(0)
    // A daemon can be offline; the pipeline row is stale, never offline.
    const pipelineRow = screen
      .getAllByText('github.com/acme/api · Security scan')[0]
      .closest('tr') as HTMLElement
    expect(within(pipelineRow).getByText('Stale')).toBeInTheDocument()
    expect(within(pipelineRow).queryByText(/offline/i)).not.toBeInTheDocument()
    expect(screen.getAllByText('Offline').length).toBeGreaterThan(0)
    // Header counts per mode.
    expect(screen.getByText('CI pipelines fresh')).toBeInTheDocument()
    expect(screen.getByText('of 3')).toBeInTheDocument()
    await userEvent.click(pipelineRow)
    expect(onOpenRunner).toHaveBeenCalledWith('p1')
    expect(onOpenDaemon).not.toHaveBeenCalled()
  })
})
