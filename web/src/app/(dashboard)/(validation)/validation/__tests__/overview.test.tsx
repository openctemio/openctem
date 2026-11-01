/**
 * Validation › Overview (research/370): the waiting list shows only queues
 * with something in them, each count links to the list it counts, a module
 * that is off leaves the page without a request to its API, and only owners
 * and admins see the "turn on in Modules" line.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import ValidationOverviewPage from '../page'
import {
  REOPENED_RECENTLY,
  STILL_REPRODUCES,
  VALIDATED_RECENTLY,
  awaitingValidationQuery,
  findingsHref,
  switchedOffModules,
} from '@/features/validation/lib/overview-queries'

const state = {
  moduleIds: ['findings', 'pentest', 'attack_simulation', 'control_testing', 'mitre_coverage'],
  notEntitled: [] as string[],
  perms: new Set<string>(),
  counts: {} as Record<string, number>,
  retestsDue: 3,
  campaigns: [{ status: 'in_progress' }, { status: 'completed' }, { status: 'planning' }],
  coverage: {
    p0_p1_total: 50,
    p0_p1_validated: 34,
    by_priority: [
      { priority: 'P0', total: 12, validated: 9 },
      { priority: 'P1', total: 38, validated: 25 },
      { priority: 'P2', total: 5, validated: 1 },
    ],
  } as Record<string, unknown> | undefined,
  readyToClose: 2 as number | undefined,
  modulesLoading: false,
}
const countCalls: { href: string; enabled: boolean }[] = []
const pentestQueries: unknown[] = []
const campaignQueries: unknown[] = []

vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/context/brand-provider', () => ({ useDocsHref: () => (h: string) => h }))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: (id: string) => state.moduleIds.includes(id),
  useTenantModules: () => ({
    moduleIds: state.moduleIds,
    notEntitledModuleIds: state.notEntitled,
    isLoading: state.modulesLoading,
  }),
}))
vi.mock('@/lib/permissions', () => ({
  Permission: {
    PentestRead: 'validation:read',
    FindingsVerify: 'findings:verify',
    TeamUpdate: 'team:update',
  },
  useHasPermission: (p: string) => state.perms.has(p),
}))
vi.mock('@/features/findings/api/use-findings-count', () => ({
  useFindingsCount: (f: { extra: Record<string, string> }, enabled = true) => {
    countCalls.push({ href: findingsHref(f.extra), enabled })
    return state.counts[findingsHref(f.extra)]
  },
}))
vi.mock('@/features/closure-review/api', () => ({
  useReadyToCloseCount: (fetch: boolean) => (fetch ? state.readyToClose : undefined),
}))
vi.mock('@/features/validation/api/use-validation-coverage', () => ({
  useValidationCoverage: () => ({
    data: state.coverage,
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
}))
vi.mock('@/features/pentest/api/use-pentest-api', () => ({
  RETEST_PENDING_STATUSES: ['in_progress', 'fix_applied'],
  useAdaptedPentestFindingPage: (q: unknown) => {
    pentestQueries.push(q)
    return { data: q ? { total: state.retestsDue, data: [] } : undefined }
  },
  useAdaptedCampaigns: (f: unknown) => {
    campaignQueries.push(f)
    return { data: f === null ? undefined : { data: state.campaigns } }
  },
}))

const ALL_MODULES = [
  'findings',
  'pentest',
  'attack_simulation',
  'control_testing',
  'mitre_coverage',
]

beforeEach(() => {
  state.moduleIds = [...ALL_MODULES]
  state.notEntitled = []
  state.perms = new Set(['validation:read', 'findings:verify'])
  state.counts = {
    [findingsHref(awaitingValidationQuery(true))]: 12,
    [findingsHref(VALIDATED_RECENTLY)]: 14,
    [findingsHref(STILL_REPRODUCES)]: 2,
    [findingsHref(REOPENED_RECENTLY)]: 0,
  }
  state.readyToClose = 2
  state.modulesLoading = false
  countCalls.length = 0
  pentestQueries.length = 0
  campaignQueries.length = 0
})

describe('Validation overview', () => {
  it('does not count the awaiting queue until the module list has loaded', () => {
    state.modulesLoading = true
    render(<ValidationOverviewPage />)
    const awaiting = countCalls.filter((c) => c.href.includes('status=fix_applied'))
    expect(awaiting.length).toBeGreaterThan(0)
    expect(awaiting.every((c) => !c.enabled)).toBe(true)
  })

  it('lists each waiting queue with its count and the link to the list it counts', () => {
    render(<ValidationOverviewPage />)
    const list = screen.getByTestId('validation-waiting')
    const rows = within(list).getAllByRole('listitem')
    expect(rows.map((r) => r.textContent)).toEqual([
      expect.stringContaining('12Fixes waiting for validation'),
      expect.stringContaining('3Pentest retests due'),
      expect.stringContaining('2Ready to close'),
      expect.stringContaining('2Open campaigns'),
    ])
    expect(within(rows[0]).getByRole('link', { name: 'Validate' })).toHaveAttribute(
      'href',
      '/findings?state=open&status=fix_applied&source_not=pentest'
    )
    expect(within(rows[1]).getByRole('link')).toHaveAttribute('href', '/validation/retests')
    expect(within(rows[2]).getByRole('link')).toHaveAttribute('href', '/findings/ready-to-close')
  })

  it('leaves out an empty queue and says so when nothing waits', () => {
    state.counts[findingsHref(awaitingValidationQuery(true))] = 0
    state.retestsDue = 0
    state.readyToClose = 0
    state.campaigns = []
    render(<ValidationOverviewPage />)
    expect(screen.queryByTestId('validation-waiting')).toBeNull()
    expect(screen.getByText(/Nothing is waiting for you/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Attack simulation' })).toHaveAttribute(
      'href',
      '/attack-simulation'
    )
    state.retestsDue = 3
    state.campaigns = [{ status: 'in_progress' }, { status: 'completed' }, { status: 'planning' }]
  })

  it('puts P0/P1 coverage first in the strip, with its classes and definition link', () => {
    render(<ValidationOverviewPage />)
    const tile = screen.getByRole('link', { name: /P0\/P1 validation coverage/ })
    expect(tile).toHaveAttribute('href', '/findings?state=closed&priority_class=P0%2CP1')
    expect(tile).toHaveTextContent('68%')
    expect(tile).toHaveTextContent('P0 9 of 12')
    expect(tile).toHaveTextContent('P1 25 of 38')
    expect(tile).not.toHaveTextContent('P2')
    expect(screen.getByRole('link', { name: /How coverage is measured/ })).toHaveAttribute(
      'href',
      'https://docs.openctem.io/user-guide/07-validation/#validation-overview'
    )
  })

  it('shows a dash, not 0%, when no P0/P1 finding is closed', () => {
    const saved = state.coverage
    state.coverage = { p0_p1_total: 0, p0_p1_validated: 0, by_priority: [] }
    render(<ValidationOverviewPage />)
    const tile = screen.getByRole('link', { name: /P0\/P1 validation coverage/ })
    expect(tile).toHaveTextContent('–')
    expect(tile).not.toHaveTextContent('0%')
    state.coverage = saved
  })

  it('links every outcome tile to its findings list and keeps a zero neutral', () => {
    render(<ValidationOverviewPage />)
    const still = screen.getByRole('link', { name: /Still reproduces/ })
    expect(still).toHaveAttribute('href', '/findings?state=open&validation=reproducible')
    expect(still).toHaveTextContent('2')
    expect(screen.getByRole('link', { name: /Validated, last 30 days/ })).toHaveAttribute(
      'href',
      '/findings?state=fixed&validation=not_reproducible&resolved_at_gte=-P30D'
    )
    expect(screen.getByRole('link', { name: /Reopened, last 30 days/ })).toHaveAttribute(
      'href',
      '/findings?state=all&last_reopened_at_gte=-P30D'
    )
  })

  it('with pentest off: no pentest request, its rows leave, awaiting counts pentest findings too', () => {
    state.moduleIds = ['findings', 'mitre_coverage']
    state.counts[findingsHref(awaitingValidationQuery(false))] = 7
    render(<ValidationOverviewPage />)
    expect(pentestQueries.every((q) => q === null)).toBe(true)
    expect(campaignQueries.every((q) => q === null)).toBe(true)
    expect(screen.queryByText('Pentest retests due')).toBeNull()
    expect(screen.queryByText('Open campaigns')).toBeNull()
    expect(screen.getByRole('link', { name: 'Validate' })).toHaveAttribute(
      'href',
      '/findings?state=open&status=fix_applied'
    )
  })

  it('tells owners and admins which modules are off, and nobody else', () => {
    state.moduleIds = ['findings', 'pentest', 'mitre_coverage']
    const { unmount } = render(<ValidationOverviewPage />)
    expect(screen.queryByTestId('validation-modules-off')).toBeNull()
    unmount()

    state.perms.add('team:update')
    render(<ValidationOverviewPage />)
    const hint = screen.getByTestId('validation-modules-off')
    expect(hint).toHaveTextContent('Attack simulation and Control testing are switched off.')
    expect(within(hint).getByRole('link', { name: 'Turn on in Modules' })).toHaveAttribute(
      'href',
      '/settings/modules'
    )
  })
})

describe('switchedOffModules', () => {
  it('names entitled modules that are off', () => {
    expect(switchedOffModules(['findings', 'pentest'], ['mitre_coverage'], false)).toEqual([
      'attack_simulation',
      'control_testing',
    ])
  })
  it('names none while loading or when the API reports no module list', () => {
    expect(switchedOffModules(['findings'], [], true)).toEqual([])
    expect(switchedOffModules([], [], false)).toEqual([])
  })
})
