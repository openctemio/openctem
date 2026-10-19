/**
 * The Review step's refused targets, grouped by reason with one action per
 * group (RFC-054 §6.4), and the routing note.
 */
import { describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

vi.mock('@/lib/api/client', () => ({
  get: vi.fn().mockResolvedValue({}),
  post: vi.fn(),
  put: vi.fn(),
  del: vi.fn(),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const { RefusalGroups, GROUP_EXAMPLES } = await import('../refusal-groups')
const { RoutingNote } = await import('../review-step')

const proof = (i: number) => ({
  target: `h${i}.example.com`,
  allowed: false,
  code: 'proof_required',
  fixes: [{ action: 'use_tenant_sensor' }],
})
const zone = (i: number) => ({
  target: `int${i}.example.com`,
  allowed: false,
  code: 'zone_none',
  resolved: [`10.0.0.${i}`],
})
const results = [
  ...Array.from({ length: 12 }, (_, i) => proof(i)),
  ...Array.from({ length: 3 }, (_, i) => zone(i)),
]

describe('RefusalGroups', () => {
  it('shows one group per reason with its count, a few examples and Show all', async () => {
    const user = userEvent.setup()
    render(<RefusalGroups results={results} onRemove={vi.fn()} onRecheck={vi.fn()} />)
    const proofGroup = screen.getByTestId('refusal-group-proof')
    expect(
      within(proofGroup).getByText('12 need a verified domain for shared sensors')
    ).toBeInTheDocument()
    expect(within(proofGroup).getAllByRole('listitem')).toHaveLength(GROUP_EXAMPLES)
    await user.click(within(proofGroup).getByRole('button', { name: 'Show all 12' }))
    expect(within(proofGroup).getAllByRole('listitem')).toHaveLength(12)
    expect(
      screen.getByText('3 resolve to private addresses outside every scan zone')
    ).toBeInTheDocument()
    // Not one row-level "Proof needed" button per target.
    expect(screen.queryByText('Proof needed')).not.toBeInTheDocument()
  })

  it('explains a private address in plain words with the resolved address', () => {
    render(<RefusalGroups results={[zone(7)]} onRemove={vi.fn()} onRecheck={vi.fn()} />)
    expect(
      screen.getByText(
        'Resolves to 10.0.0.7, an internal address: scanning it would hit your own network.'
      )
    ).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Set up a scan zone' })).toHaveAttribute(
      'href',
      '/sensors?tab=zones'
    )
  })

  it('offers one bulk action per group: own sensor, remove the group', async () => {
    const user = userEvent.setup()
    const onRemove = vi.fn()
    const onUseOwnSensors = vi.fn()
    render(
      <RefusalGroups
        results={results}
        onRemove={onRemove}
        onUseOwnSensors={onUseOwnSensors}
        onRecheck={vi.fn()}
      />
    )
    const proofGroup = screen.getByTestId('refusal-group-proof')
    await user.click(within(proofGroup).getByRole('button', { name: 'Run on your own sensor' }))
    expect(onUseOwnSensors).toHaveBeenCalledTimes(1)
    await user.click(within(proofGroup).getByRole('button', { name: 'Remove these 12 targets' }))
    expect(onRemove).toHaveBeenCalledWith(results.slice(0, 12).map((r) => r.target))
    // Zone targets cannot move to the own sensor by switching: no such button.
    const zoneGroup = screen.getByTestId('refusal-group-zone')
    expect(
      within(zoneGroup).queryByRole('button', { name: 'Run on your own sensor' })
    ).not.toBeInTheDocument()
  })

  it('does not offer the own sensor for intrusive checks or when already on own sensors', () => {
    const { rerender } = render(
      <RefusalGroups
        results={results}
        probeTier={2}
        onRemove={vi.fn()}
        onUseOwnSensors={vi.fn()}
        onRecheck={vi.fn()}
      />
    )
    expect(screen.queryByRole('button', { name: 'Run on your own sensor' })).not.toBeInTheDocument()
    rerender(
      <RefusalGroups
        results={results}
        sensorPreference="tenant"
        onRemove={vi.fn()}
        onUseOwnSensors={vi.fn()}
        onRecheck={vi.fn()}
      />
    )
    expect(screen.queryByRole('button', { name: 'Run on your own sensor' })).not.toBeInTheDocument()
  })
})

describe('RoutingNote', () => {
  it('explains why Auto picked the own sensor', () => {
    render(
      <RoutingNote
        routing={{
          preference: 'auto',
          runs_on: 'tenant',
          reason: 'platform_needs_proof',
          sensor: { id: 's', name: 'sensor-docker-01' },
        }}
      />
    )
    expect(
      screen.getByText(
        /runs on your sensor sensor-docker-01, because shared sensors need a verified domain/
      )
    ).toBeInTheDocument()
  })

  it('says when the scan would wait', () => {
    render(
      <RoutingNote
        routing={{ preference: 'tenant', runs_on: 'waits', reason: 'no_tenant_sensor' }}
      />
    )
    expect(screen.getByTestId('routing-note')).toHaveTextContent('none of your sensors')
  })
})
