/**
 * The Targets step as a whole: what is entered is grouped by kind on the
 * result side with each kind's setting next to it, a setting shows only when
 * what was entered uses it, the ranges choice shown is the mode the API runs
 * (live hosts first for a new single-scanner scan, every address for a
 * workflow without Host discovery), and "From scope" shows only to people who
 * can read the scope.
 */
import * as React from 'react'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const perms = vi.hoisted(() => ({ scope: true }))
const workflow = vi.hoisted(() => ({ value: undefined as unknown }))
const coreAddrs = vi.hoisted(() => ({ value: undefined as unknown }))
const excluded = vi.hoisted(() => ({ calls: [] as unknown[] }))

vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({
    can: (p: string) => (p === 'attack_surface:scope:read' ? perms.scope : true),
  }),
}))
vi.mock('@/lib/api/sensor-hooks', () => ({
  useSensorCoreAddresses: () => ({ data: coreAddrs.value }),
}))
vi.mock('@/features/assets/api/triage-api', () => ({
  createExclusions: async (items: { pattern: string }[], opts: unknown) => {
    excluded.calls.push({ items, opts })
    return {
      results: items.map((i) => ({ ...i, result: 'created' })),
      created: items.length,
      existing: 0,
      refused: 0,
    }
  },
}))
vi.mock('@/lib/api/scan-workflow-hooks', () => ({
  useScanWorkflow: () => ({ data: workflow.value }),
}))
vi.mock('../../../hooks/use-targets-check', async (orig) => {
  const { directTargets } = await import('../../../lib/scan-form')
  return {
    ...(await orig<typeof import('../../../hooks/use-targets-check')>()),
    useTargetsCheck: (data: Parameters<typeof directTargets>[0]) => ({
      check: {
        available: true,
        results: [],
        resultFor: () => undefined,
        isLoading: false,
        error: undefined,
        tier: 1,
        recheck: vi.fn(),
      },
      readiness: { state: 'unknown', scannable: 0, unresolved: [], refused: 0 },
      sent: directTargets(data),
      sensorPreference: 'auto',
    }),
  }
})
vi.mock('../../../hooks/use-coverage-expansion', () => ({
  useCoverageExpansion: (typed: string[]) => ({
    added: [],
    roots: typed.filter((x) => /[a-z]/i.test(x) && !x.includes('/')),
    nameCount: 0,
    isLoading: false,
  }),
}))
vi.mock('../../../hooks/use-selector-preview', () => ({
  useSelectorPreview: () => ({ previews: [], isLoading: false, enabled: true }),
}))
vi.mock('../../target-picker/asset-source', () => ({ AssetSource: () => null }))
vi.mock('../../target-picker/group-source', () => ({ GroupSource: () => null }))
vi.mock('../../target-picker/scope-source', () => ({
  ScopeSource: () => <p>scope source</p>,
}))

import { DEFAULT_NEW_SCAN, type NewScanFormData } from '../../../types'
import { TargetsStep } from '../targets-step'

function Harness({
  initial,
  savedScan,
}: {
  initial: Partial<NewScanFormData>
  savedScan?: boolean
}) {
  const [data, setData] = React.useState<NewScanFormData>({ ...DEFAULT_NEW_SCAN, ...initial })
  return (
    <TargetsStep
      data={data}
      onChange={(patch) => setData((d) => ({ ...d, ...patch }))}
      savedScan={savedScan}
      showCoverage={!savedScan}
    />
  )
}

const withTargets = (customTargets: string[], extra: Partial<NewScanFormData> = {}) => ({
  ...extra,
  targets: { ...DEFAULT_NEW_SCAN.targets, customTargets },
})

describe('TargetsStep', () => {
  beforeEach(() => {
    perms.scope = true
    workflow.value = undefined
    coreAddrs.value = undefined
    excluded.calls = []
  })

  it('warns when range targets cover a sensor resolver, and excludes it on request', async () => {
    const user = userEvent.setup()
    coreAddrs.value = {
      items: [
        {
          sensor_id: 's1',
          sensor_name: 'scanner-hn',
          addresses: [
            { address: '10.0.0.53', role: 'resolver' },
            { address: '192.0.2.1', role: 'gateway' },
          ],
        },
      ],
    }
    render(<Harness initial={withTargets(['10.0.0.0/24', 'www.example.com'])} />)
    const warning = screen.getByTestId('core-infra-warning')
    expect(warning).toHaveTextContent('10.0.0.53')
    expect(warning).toHaveTextContent('scanner-hn')
    expect(warning).not.toHaveTextContent('192.0.2.1')
    await user.click(within(warning).getByRole('button', { name: 'Exclude these' }))
    expect(excluded.calls).toEqual([
      {
        items: [{ exclusion_type: 'ip_address', pattern: '10.0.0.53' }],
        opts: expect.objectContaining({ kind: 'do_not_scan' }),
      },
    ])
    expect(screen.queryByTestId('core-infra-warning')).not.toBeInTheDocument()
  })

  it('shows no core infrastructure warning when no target covers it', () => {
    coreAddrs.value = {
      items: [
        {
          sensor_id: 's1',
          sensor_name: 'x',
          addresses: [{ address: '10.0.0.53', role: 'resolver' }],
        },
      ],
    }
    render(<Harness initial={withTargets(['203.0.113.0/24'])} />)
    expect(screen.queryByTestId('core-infra-warning')).not.toBeInTheDocument()
  })

  it('groups ranges on the result side with the ranges choice beside them, live hosts first for a new scan', () => {
    render(<Harness initial={withTargets(['203.0.113.0/24', '198.51.100.0/24'])} />)
    const ranges = screen.getByTestId('target-group-ranges')
    expect(within(ranges).getByRole('heading', { name: /Address ranges/ })).toHaveTextContent('2')
    expect(within(ranges).getByRole('radio', { name: 'Live hosts first' })).toBeChecked()
    // No domain entered: no coverage choice, no domains group.
    expect(screen.queryByTestId('coverage-choice')).not.toBeInTheDocument()
    expect(screen.queryByTestId('target-group-domains')).not.toBeInTheDocument()
  })

  it('a workflow without Host discovery shows its ranges swept, as the API saves it', () => {
    workflow.value = { steps: [{ capabilities: ['scan.ports'] }] }
    render(
      <Harness initial={withTargets(['203.0.113.0/24'], { mode: 'workflow', workflowId: 'w1' })} />
    )
    expect(screen.getByRole('radio', { name: 'Every address' })).toBeChecked()
    expect(screen.getByRole('radio', { name: 'Live hosts first' })).toBeDisabled()
  })

  it('shows the coverage choice next to the domains only, and scans a domain as its wildcard', async () => {
    const user = userEvent.setup()
    render(<Harness initial={withTargets(['example.com', '198.51.100.7'])} />)
    const domains = screen.getByTestId('target-group-domains')
    expect(within(domains).getByTestId('coverage-choice')).toBeInTheDocument()
    expect(within(screen.getByTestId('target-group-addresses')).queryByRole('radio')).toBeNull()
    await user.click(within(domains).getByRole('radio', { name: 'With subdomains' }))
    expect(within(domains).getByText(/scanned as \*\.example\.com/)).toBeInTheDocument()
    // A wildcard is resolved again at every run: its options appear.
    expect(screen.getByTestId('options-summary')).toHaveTextContent('only names that resolve')
  })

  it('offers "From scope" only to people who can read the scope', async () => {
    const user = userEvent.setup()
    const { unmount } = render(<Harness initial={withTargets([])} />)
    await user.click(screen.getByTestId('from-scope'))
    expect(await screen.findByText('scope source')).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /Scope/ })).toHaveAttribute('data-state', 'active')
    unmount()

    perms.scope = false
    render(<Harness initial={withTargets([])} />)
    expect(screen.queryByTestId('from-scope')).not.toBeInTheDocument()
  })

  it('works on a saved scan too (Edit): no coverage choice, a range without a mode is swept', () => {
    render(<Harness initial={withTargets(['example.com', '203.0.113.0/24'])} savedScan />)
    expect(screen.queryByTestId('coverage-choice')).not.toBeInTheDocument()
    expect(screen.getByRole('radio', { name: 'Every address' })).toBeChecked()
  })
})
