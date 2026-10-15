import { describe, it, expect } from 'vitest'
import { ruleEndProblem, MAX_RULE_DAYS } from '../suppression-form-dialog'

const now = new Date('2026-10-15T12:00:00Z')
const local = (d: Date) => {
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}
const days = (n: number) => new Date(now.getTime() + n * 24 * 60 * 60 * 1000)

describe('ruleEndProblem', () => {
  it('requires an end date', () => {
    expect(ruleEndProblem('', now)).toBe('missing')
  })
  it('refuses an end in the past', () => {
    expect(ruleEndProblem(local(days(-1)), now)).toBe('past')
  })
  it('refuses an end beyond a year', () => {
    expect(ruleEndProblem(local(days(MAX_RULE_DAYS + 2)), now)).toBe('tooLate')
  })
  it('accepts the default and a date within a year', () => {
    expect(ruleEndProblem(local(days(90)), now)).toBeNull()
    expect(ruleEndProblem(local(days(MAX_RULE_DAYS - 1)), now)).toBeNull()
  })
})
