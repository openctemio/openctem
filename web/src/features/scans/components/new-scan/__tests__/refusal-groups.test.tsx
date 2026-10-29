/**
 * Refused targets grouped by reason with the server's ranked remedies (the
 * Targets and Review steps share it), the readiness line, and the routing
 * note.
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
vi.mock('@/features/attack-surface/components/easm-verify-domain-dialog', () => ({
  VerifyDomainDialog: ({ domain }: { domain: string | null }) =>
    domain ? <div role="dialog" aria-label={`verify ${domain}`} /> : null,
}))

const { RefusalGroups, ReadinessLine, GROUP_EXAMPLES } = await import('../refusal-groups')
const { RoutingNote } = await import('../review-step')
type Result = import('@/features/scope').ApiScopeCheckResult

const proof = (i: number): Result => ({
  target: `h${i}.example.com`,
  allowed: false,
  code: 'proof_required',
  fixes: [{ action: 'use_tenant_sensor' }],
  remedies: [{ action: 'run_on_tenant_sensor' }, { action: 'remove' }],
})
const zone = (i: number): Result => ({
  target: `int${i}.example.com`,
  allowed: false,
  code: 'zone_none',
  resolved: [`10.0.0.${i}`],
  remedies: [{ action: 'remove' }],
})
const results: Result[] = [
  ...Array.from({ length: 12 }, (_, i) => proof(i)),
  ...Array.from({ length: 3 }, (_, i) => zone(i)),
]

describe('RefusalGroups', () => {
  it('shows one group per reason with its count, a few examples and Show all', async () => {
    const user = userEvent.setup()
    render(<RefusalGroups results={results} onRemove={vi.fn()} onRecheck={vi.fn()} />)
    const proofGroup = screen.getByTestId('refusal-group-proof')
    expect(
      within(proofGroup).getByText('12 targets need a verified domain for shared sensors')
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
    await user.click(within(proofGroup).getByRole('button', { name: 'Run on my sensor' }))
    expect(onUseOwnSensors).toHaveBeenCalledTimes(1)
    await user.click(within(proofGroup).getByRole('button', { name: 'Remove these 12 targets' }))
    expect(onRemove).toHaveBeenCalledWith(results.slice(0, 12).map((r) => r.target))
    // Zone targets cannot move to the own sensor by switching: no such button.
    const zoneGroup = screen.getByTestId('refusal-group-zone')
    expect(
      within(zoneGroup).queryByRole('button', { name: 'Run on my sensor' })
    ).not.toBeInTheDocument()
  })

  it('does not offer the own sensor when already on own sensors', () => {
    render(
      <RefusalGroups
        results={results}
        sensorPreference="tenant"
        onRemove={vi.fn()}
        onUseOwnSensors={vi.fn()}
        onRecheck={vi.fn()}
      />
    )
    expect(screen.queryByRole('button', { name: 'Run on my sensor' })).not.toBeInTheDocument()
  })

  it('shows the server ranking: the first remedy is the primary button, remove last', async () => {
    const user = userEvent.setup()
    const onUseOwnSensors = vi.fn()
    render(
      <RefusalGroups
        results={[
          {
            target: 'www.acme.example',
            allowed: false,
            code: 'proof_required',
            remedies: [
              { action: 'run_on_tenant_sensor' },
              { action: 'verify_domain', domain: 'acme.example' },
              { action: 'remove' },
            ],
          },
        ]}
        onRemove={vi.fn()}
        onUseOwnSensors={onUseOwnSensors}
        onRecheck={vi.fn()}
      />
    )
    const buttons = within(screen.getByTestId('refusal-remedies')).getAllByRole('button')
    expect(buttons.map((b) => b.textContent)).toEqual([
      'Run on my sensor',
      'Verify acme.example',
      'Remove this target',
    ])
    expect(buttons[0].className).toMatch(/bg-primary/)
    expect(buttons[1].className).not.toMatch(/bg-primary /)
    await user.click(buttons[1])
    expect(screen.getByRole('dialog', { name: 'verify acme.example' })).toBeInTheDocument()
  })

  it('without an own sensor online, verify is the primary fix', () => {
    render(
      <RefusalGroups
        results={[
          {
            target: 'www.acme.example',
            allowed: false,
            code: 'proof_required',
            remedies: [{ action: 'verify_domain', domain: 'acme.example' }, { action: 'remove' }],
          },
        ]}
        onRemove={vi.fn()}
        onUseOwnSensors={vi.fn()}
        onRecheck={vi.fn()}
      />
    )
    const [first] = within(screen.getByTestId('refusal-remedies')).getAllByRole('button')
    expect(first).toHaveTextContent('Verify acme.example')
  })

  it('lowers the intensity to the tier the server found, only when the form allows it', async () => {
    const user = userEvent.setup()
    const onLowerIntensity = vi.fn()
    const tierRefusal: Result[] = [
      {
        target: 'app.acme.example',
        allowed: false,
        code: 'tier_exceeds',
        remedies: [{ action: 'lower_intensity', tier: 1 }, { action: 'remove' }],
      },
    ]
    const { rerender } = render(
      <RefusalGroups
        results={tierRefusal}
        onRemove={vi.fn()}
        onLowerIntensity={onLowerIntensity}
        canLowerIntensity={() => true}
        onRecheck={vi.fn()}
      />
    )
    await user.click(screen.getByRole('button', { name: 'Lower intensity to Active' }))
    expect(onLowerIntensity).toHaveBeenCalledWith(1)
    rerender(
      <RefusalGroups
        results={tierRefusal}
        onRemove={vi.fn()}
        onLowerIntensity={onLowerIntensity}
        canLowerIntensity={() => false}
        onRecheck={vi.fn()}
      />
    )
    expect(screen.queryByRole('button', { name: /Lower intensity/ })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Remove this target' })).toBeInTheDocument()
  })

  it('always offers remove, even when the answer lists no remedies', async () => {
    const user = userEvent.setup()
    const onRemove = vi.fn()
    render(
      <RefusalGroups
        results={[{ target: 'x.example', allowed: false, code: 'no_entry' }]}
        onRemove={onRemove}
        onRecheck={vi.fn()}
      />
    )
    await user.click(screen.getByRole('button', { name: 'Remove this target' }))
    expect(onRemove).toHaveBeenCalledWith(['x.example'])
  })
})

describe('ReadinessLine', () => {
  it('says how many targets, ready and blocked on one line, without middle dots', () => {
    render(<ReadinessLine total={3} ready={2} blocked={1} />)
    const line = screen.getByTestId('readiness-line')
    expect(line).toHaveTextContent('3 targets')
    expect(line).toHaveTextContent('2 ready')
    expect(line).toHaveTextContent('1 blocked')
    expect(line.textContent).not.toMatch(/·/)
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
