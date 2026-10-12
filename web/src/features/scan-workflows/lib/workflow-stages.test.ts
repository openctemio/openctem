import { describe, expect, it } from 'vitest'
import type { ScanWorkflowStep } from '@/lib/api'
import { formatDuration, planStages } from './workflow-stages'

const s = (key: string, deps: string[] = [], timeout = 600): ScanWorkflowStep => ({
  id: key,
  step_key: key,
  name: key,
  order: 1,
  ui_position: { x: 0, y: 0 },
  capabilities: [],
  depends_on: deps,
  timeout_seconds: timeout,
  max_retries: 0,
  retry_delay_seconds: 0,
})

const keys = (stages: ScanWorkflowStep[][]) => stages.map((g) => g.map((x) => x.step_key))

describe('planStages', () => {
  it('fan-out then fan-in: parallel steps share a stage, the join waits for both', () => {
    // subdomains -> (http, ports) -> vulns ; screenshots after http
    const plan = planStages([
      s('subdomains', [], 300),
      s('http', ['subdomains'], 600),
      s('ports', ['subdomains'], 1800),
      s('vulns', ['http', 'ports'], 3600),
      s('shots', ['http'], 900),
    ])
    expect(keys(plan.stages)).toEqual([['subdomains'], ['http', 'ports'], ['vulns', 'shots']])
    expect(plan.waitsFor.vulns).toEqual(['http', 'ports'])
    expect(plan.maxConcurrent).toBe(2)
    expect(plan.criticalPath.map((x) => x.step_key)).toEqual(['subdomains', 'ports', 'vulns'])
    expect(plan.estimatedSeconds).toBe(300 + 1800 + 3600)
    expect(plan.problems).toEqual([])
  })

  it('a step with a long chain lands in a later stage than its parallel peers', () => {
    const plan = planStages([s('a'), s('b', ['a']), s('c', ['b']), s('d', ['a', 'c'])])
    expect(keys(plan.stages)).toEqual([['a'], ['b'], ['c'], ['d']])
  })

  it('independent roots run together', () => {
    const plan = planStages([s('code'), s('deps'), s('iac')])
    expect(keys(plan.stages)).toEqual([['code', 'deps', 'iac']])
    expect(plan.maxConcurrent).toBe(3)
  })

  it('a cycle is a problem, never a crash', () => {
    const plan = planStages([s('a'), s('b', ['a', 'c']), s('c', ['b'])])
    expect(plan.problems).toEqual([{ kind: 'cycle', steps: ['b', 'c'] }])
    expect(keys(plan.stages)).toEqual([['a']])
  })

  it('a dependency on a missing step is a problem; the step still shows', () => {
    const plan = planStages([s('a', ['ghost'])])
    expect(plan.problems).toEqual([{ kind: 'missing', steps: ['a'], missing: ['ghost'] }])
    expect(keys(plan.stages)).toEqual([['a']])
  })

  it('an empty workflow has no stages', () => {
    expect(planStages([])).toMatchObject({ stages: [], maxConcurrent: 0, estimatedSeconds: 0 })
  })
})

describe('formatDuration', () => {
  it('reads like a person would say it', () => {
    expect(formatDuration(30)).toBe('30 s')
    expect(formatDuration(2700)).toBe('45 min')
    expect(formatDuration(3600)).toBe('1 h')
    expect(formatDuration(5400)).toBe('1 h 30 min')
  })
})
