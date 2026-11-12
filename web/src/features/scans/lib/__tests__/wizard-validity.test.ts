import { describe, expect, it } from 'vitest'
import { DEFAULT_NEW_SCAN, type NewScanFormData } from '../../types'
import {
  estimateJobs,
  firstIssue,
  issueCount,
  scanStepIssues,
  stepStatuses,
  stepsThatRun,
} from '../wizard-validity'

const STEPS = ['basic', 'targets', 'options', 'schedule', 'review'] as const

function form(patch: Partial<NewScanFormData> = {}): NewScanFormData {
  return { ...DEFAULT_NEW_SCAN, ...patch }
}

const valid = form({
  name: 'Weekly web',
  scannerName: 'nuclei',
  targets: { ...DEFAULT_NEW_SCAN.targets, customTargets: ['app.example.com'] },
})

describe('scanStepIssues', () => {
  it('a complete form has no problem on any step', () => {
    expect(issueCount(scanStepIssues(valid), STEPS)).toBe(0)
    expect(firstIssue(scanStepIssues(valid), STEPS)).toBeNull()
  })

  it('an empty form has problems on What and Targets only', () => {
    const issues = scanStepIssues(form())
    expect(issues.basic).toHaveLength(1)
    expect(issues.targets).toHaveLength(1)
    expect(issues.options).toEqual([])
    expect(issues.schedule).toEqual([])
    expect(firstIssue(issues, STEPS)?.step).toBe('basic')
  })

  it('an invalid typed entry is a Targets problem', () => {
    const issues = scanStepIssues({
      ...valid,
      targets: { ...valid.targets, customTargets: ['app.example.com', '10.0.0.0/7'] },
    })
    expect(issues.targets[0]).toMatch(/not a target/i)
    expect(firstIssue(issues, STEPS)).toEqual({ step: 'targets', message: issues.targets[0] })
  })

  it('every target blocked by the scope check is a Targets problem', () => {
    const issues = scanStepIssues(valid, {
      readiness: { state: 'blocked', scannable: 0, unresolved: [], refused: 1 },
    })
    expect(issues.targets).toHaveLength(1)
  })

  it('an answer still on its way never blocks', () => {
    const issues = scanStepIssues(valid, {
      readiness: { state: 'unknown', scannable: 0, unresolved: [], refused: 0 },
    })
    expect(issues.targets).toEqual([])
  })

  it('a one-off run in the past is a Schedule problem', () => {
    const issues = scanStepIssues({
      ...valid,
      schedule: {
        ...valid.schedule,
        runImmediately: false,
        frequency: 'once',
        runAtDate: '2020-01-01',
        runAtTime: '10:00',
        timezone: 'UTC',
      },
    })
    expect(issues.schedule).toHaveLength(1)
  })
})

describe('stepStatuses', () => {
  const issues = scanStepIssues(form())

  it('shows nothing on steps not visited yet', () => {
    const s = stepStatuses(issues, STEPS, new Set(), false)
    expect(Object.values(s).every((x) => x.state === 'idle')).toBe(true)
  })

  it('shows problems on visited steps and valid on the clean ones', () => {
    const s = stepStatuses(issues, STEPS, new Set(['basic', 'options']), false)
    expect(s.basic).toEqual({ state: 'invalid', count: 1 })
    expect(s.options).toEqual({ state: 'valid', count: 0 })
    expect(s.targets.state).toBe('idle')
  })

  it('shows every problem after a create attempt; Review stays a plain step', () => {
    const s = stepStatuses(issues, STEPS, new Set(), true)
    expect(s.basic.state).toBe('invalid')
    expect(s.targets.state).toBe('invalid')
    expect(s.review.state).toBe('idle')
  })
})

describe('estimateJobs', () => {
  it.each([
    [0, 10, 0],
    [1, 10, 1],
    [10, 10, 1],
    [245, 10, 25],
    [5, 0, 1],
  ])('%i targets at %i per job is %i jobs', (n, per, jobs) => {
    expect(estimateJobs(n, per)).toBe(jobs)
  })
})

describe('stepsThatRun (tool readiness is information, never a blocker)', () => {
  it('counts ready and waiting steps out of all; skipped and tool-less ones do not run', () => {
    expect(
      stepsThatRun({
        state: 'blocked',
        steps: [
          { step_key: 'a', name: 'Subdomains', state: 'ready' },
          { step_key: 'b', name: 'Ports', state: 'waiting' },
          { step_key: 'c', name: 'Screenshots', state: 'skipped', optional: true },
          { step_key: 'd', name: 'Services', state: 'blocked', code: 'no_tool' },
        ],
      })
    ).toEqual({ run: 2, total: 4 })
  })

  it('is unknown without readiness', () => {
    expect(stepsThatRun(undefined)).toBeNull()
  })

  it('a workflow with steps that cannot run adds no problem to any step', () => {
    const issues = scanStepIssues({ ...valid, mode: 'workflow', workflowId: 'w1' })
    expect(issueCount(issues, STEPS)).toBe(0)
  })
})
