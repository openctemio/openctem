import { describe, expect, it } from 'vitest'
import {
  byReadiness,
  firstProblem,
  isRunnable,
  readinessFixHref,
  readinessLabel,
  skippedSteps,
  stepFix,
  stepFixHref,
  stepReason,
  type WorkflowReadiness,
} from './readiness'
import en from '@/lib/i18n/dictionaries/en/scans.json'
import vi from '@/lib/i18n/dictionaries/vi/scans.json'

/** A translator over one flat catalog with {var} interpolation. */
const tr =
  (dict: Record<string, string>) =>
  (key: string, fallback?: string, vars?: Record<string, string | number>) =>
    (dict[key] ?? fallback ?? key).replace(/\{(\w+)\}/g, (_, k) => String(vars?.[k] ?? `{${k}}`))

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

  it('a skipped optional step never blocks and says why, without a fix', () => {
    const skipped = {
      step_key: 'takeover',
      name: 'Takeover check',
      capability: 'check.takeover',
      state: 'skipped' as const,
      optional: true,
      code: 'no_tool',
      reason: 'Skipped: no tool runs check.takeover; the workflow runs without this step',
    }
    const ready = r('ready', [{ step_key: 'http', name: 'Web probe', state: 'ready' }, skipped])
    expect(isRunnable(ready)).toBe(true)
    expect(firstProblem(ready)).toBeUndefined()
    expect(readinessLabel(ready)).toBeUndefined()
    expect(skippedSteps(ready).map((s) => s.step_key)).toEqual(['takeover'])
    expect(stepReason(skipped, tr(en))).toContain('check.takeover')
    expect(stepReason(skipped, tr(vi))).toContain('check.takeover')
    expect(stepReason(skipped, tr(vi))).not.toBe(stepReason(skipped, tr(en)))
    expect(stepFix(skipped, tr(en))).toBeUndefined()
    expect(stepFixHref(skipped)).toBeUndefined()
  })

  it('localizes every reason code in both catalogs', () => {
    const codes = [
      'sensor_offline',
      'no_sensor_yet',
      'ci_only',
      'no_tool',
      'tool_disabled',
      'tool_not_installed',
      'no_sensor',
    ]
    for (const code of codes) {
      for (const dict of [en, vi] as Record<string, string>[]) {
        expect(dict[`scans.readiness.reason.${code}`], code).toBeTruthy()
        expect(dict[`scans.readiness.fix.${code}`], code).toBeTruthy()
      }
    }
    const step = {
      step_key: 'http',
      name: 'Web probe',
      capability: 'probe.http',
      state: 'blocked' as const,
      code: 'tool_disabled',
      tools: ['httpx'],
    }
    expect(stepReason(step, tr(en))).toBe('No enabled tool runs probe.http (httpx is turned off)')
    expect(stepFix(step, tr(vi))).toBe('Bật httpx')
    expect(stepFixHref(step)).toBe('/settings/scanning/tools')
    expect(readinessLabel(r('blocked'), tr(vi))).toBe('Không khả dụng')
  })
})
