import { describe, expect, it } from 'vitest'
import { nextWorkFinding, positionOf, stepFinding, taskFromParam } from '../lib/task-nav'

const order = ['a', 'b', 'c', 'd']

describe('task finding navigation', () => {
  it('reports "n of N" with neighbours', () => {
    expect(positionOf(order, 'c')).toEqual({ index: 3, total: 4, prev: 'b', next: 'd' })
    expect(positionOf(order, 'a').prev).toBeNull()
    expect(positionOf(order, 'd').next).toBeNull()
    expect(positionOf(order, 'zzz').index).toBe(0)
    expect(positionOf(order, null).next).toBeNull()
  })

  it('steps with j/k, clamped, starting at the ends when nothing is active', () => {
    expect(stepFinding(order, 'b', 1)).toBe('c')
    expect(stepFinding(order, 'd', 1)).toBe('d')
    expect(stepFinding(order, 'a', -1)).toBe('a')
    expect(stepFinding(order, null, 1)).toBe('a')
    expect(stepFinding(order, null, -1)).toBe('d')
    expect(stepFinding([], 'a', 1)).toBeNull()
  })

  it('moves to the next finding that still needs work, wrapping, never to itself', () => {
    const st: Record<string, string> = {
      a: 'in_progress',
      b: 'resolved',
      c: 'fix_applied',
      d: 'new',
    }
    expect(nextWorkFinding(order, (x) => st[x], 'a')).toBe('d')
    expect(nextWorkFinding(order, (x) => st[x], 'd')).toBe('a')
    expect(nextWorkFinding(order, () => 'resolved', 'a')).toBeNull()
    expect(nextWorkFinding(['a'], () => 'new', 'a')).toBeNull()
  })

  it('reads the task a finding page was opened from, and nothing else', () => {
    expect(taskFromParam('task:0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b')).toBe(
      '0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b'
    )
    expect(taskFromParam('task:../../x')).toBeNull()
    expect(taskFromParam('https://evil.example')).toBeNull()
    expect(taskFromParam(null)).toBeNull()
  })
})
