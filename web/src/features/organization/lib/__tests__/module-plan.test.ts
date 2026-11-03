import { describe, expect, it } from 'vitest'
import type { DependencyEdge } from '@/features/organization/api/use-tenant-modules'
import {
  applyToggle,
  buildDependencyIndex,
  computePlan,
  reachable,
  unavailableRequirements,
  type PlanOptions,
} from '../module-plan'

// A slice of the real graph: scope_config <- ctem_cycles <- ctem_maturity,
// compensating_controls <- control_testing, everything on core assets/findings.
const edges: DependencyEdge[] = [
  { from: 'scope_config', to: 'assets', type: 'hard', reason: '' },
  { from: 'ctem_cycles', to: 'scope_config', type: 'hard', reason: '' },
  { from: 'ctem_cycles', to: 'findings', type: 'soft', reason: '' },
  { from: 'ctem_maturity', to: 'ctem_cycles', type: 'hard', reason: '' },
  { from: 'control_testing', to: 'compensating_controls', type: 'hard', reason: '' },
  { from: 'mitre_coverage', to: 'compensating_controls', type: 'soft', reason: '' },
]
const index = buildDependencyIndex(edges)
const CORE = new Set(['assets', 'findings'])
const opts = (unavailable: string[] = []): PlanOptions => ({
  isCore: (id) => CORE.has(id),
  canEnable: (id) => !unavailable.includes(id),
})
const allOn = {
  assets: true,
  findings: true,
  scope_config: true,
  ctem_cycles: true,
  ctem_maturity: true,
  compensating_controls: true,
  control_testing: true,
  mitre_coverage: true,
}

describe('module plan', () => {
  it('ignores soft edges and walks hard ones transitively', () => {
    expect(index.requires.ctem_cycles).toEqual(['scope_config'])
    expect(reachable('scope_config', index.requiredBy)).toEqual(['ctem_cycles', 'ctem_maturity'])
    expect(reachable('compensating_controls', index.requiredBy)).toEqual(['control_testing'])
  })

  it('turning a module off turns off what needs it, and names why', () => {
    const plan = computePlan(allOn, { scope_config: false }, index, opts())
    expect(plan.changes).toEqual({ scope_config: false, ctem_cycles: false, ctem_maturity: false })
    expect(plan.offWith).toEqual({ ctem_cycles: ['scope_config'], ctem_maturity: ['scope_config'] })
    expect(plan.onWith).toEqual({})
  })

  it('never touches core modules', () => {
    const plan = computePlan(allOn, { assets: false }, index, opts())
    expect(plan.changes).toEqual({})
  })

  it('turning a module on turns on what it needs', () => {
    const saved = { ...allOn, scope_config: false, ctem_cycles: false, ctem_maturity: false }
    const plan = computePlan(saved, { ctem_maturity: true }, index, opts())
    expect(plan.changes).toEqual({ ctem_maturity: true, ctem_cycles: true, scope_config: true })
    expect(plan.onWith.scope_config).toEqual(['ctem_maturity'])
  })

  it('reports a requirement the organization cannot turn on', () => {
    const saved = { ...allOn, compensating_controls: false, control_testing: false }
    const plan = computePlan(
      saved,
      { control_testing: true },
      index,
      opts(['compensating_controls'])
    )
    expect(plan.blocked).toEqual({ control_testing: ['compensating_controls'] })
    expect(plan.changes).toEqual({ control_testing: true })
    expect(
      unavailableRequirements('control_testing', saved, index, opts(['compensating_controls']))
    ).toEqual(['compensating_controls'])
  })

  it('a later choice overrides an earlier one it contradicts', () => {
    // Off on scope, then the admin turns CTEM maturity back on: scope stays on.
    let pending = applyToggle({}, allOn, 'scope_config', false, index)
    expect(pending).toEqual({ scope_config: false })
    pending = applyToggle(pending, allOn, 'ctem_maturity', true, index)
    expect(pending).toEqual({})
    expect(computePlan(allOn, pending, index, opts()).changes).toEqual({})
  })

  it('flipping a module back to its saved state drops the change', () => {
    const pending = applyToggle({ ctem_cycles: false }, allOn, 'ctem_cycles', true, index)
    expect(pending).toEqual({})
  })

  it('records every module a cascaded module turns off with', () => {
    const plan = computePlan(allOn, { scope_config: false, ctem_cycles: false }, index, opts())
    expect(plan.offWith.ctem_maturity.sort()).toEqual(['ctem_cycles', 'scope_config'])
    expect(plan.offWith.ctem_cycles).toBeUndefined()
  })
})
