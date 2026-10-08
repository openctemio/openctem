import { describe, expect, it } from 'vitest'
import {
  byReadiness,
  firstProblem,
  isRunnable,
  readinessFixHref,
  readinessLabel,
  type WorkflowReadiness,
} from './readiness'

const r = (state: WorkflowReadiness['state'], steps: WorkflowReadiness['steps'] = []) => ({
  state,
  steps,
})

describe('workflow readiness', () => {
  it('ready and waiting can be chosen; ci_only and blocked cannot; unknown can', () => {
    expect(isRunnable(r('ready'))).toBe(true)
    expect(isRunnable(r('waiting'))).toBe(true)
    expect(isRunnable(r('ci_only'))).toBe(false)
    expect(isRunnable(r('blocked'))).toBe(false)
    expect(isRunnable(undefined)).toBe(true)
  })

  it('labels and fix links follow the first problem', () => {
    const blocked = r('blocked', [
      { step_key: 'a', name: 'A', state: 'ready' },
      {
        step_key: 'p',
        name: 'Ports',
        state: 'blocked',
        reason: 'No sensor offers Port scan',
        fix: 'Add a sensor with naabu',
      },
    ])
    expect(readinessLabel(blocked)).toBe('Not available')
    expect(firstProblem(blocked)?.step_key).toBe('p')
    expect(readinessFixHref(blocked)).toBe('/sensors')
    expect(
      readinessFixHref(
        r('blocked', [{ step_key: 'h', name: 'H', state: 'blocked', fix: 'Enable httpx' }])
      )
    ).toBe('/settings/scanning/tools')
    expect(readinessFixHref(r('ci_only', [{ step_key: 's', name: 'S', state: 'ci_only' }]))).toBe(
      '/ci-cd'
    )
    expect(readinessLabel(r('waiting'))).toBe('No capable sensor online')
    expect(readinessLabel(r('ready'))).toBeUndefined()
  })

  it('sorts runnable workflows first and keeps the order otherwise', () => {
    const items = [
      { id: 'code', readiness: r('ci_only') },
      { id: 'disc', readiness: r('ready') },
      { id: 'net', readiness: r('blocked') },
      { id: 'web', readiness: r('waiting') },
      { id: 'mine' },
    ]
    expect(byReadiness(items).map((x) => x.id)).toEqual(['disc', 'mine', 'web', 'code', 'net'])
  })
})
