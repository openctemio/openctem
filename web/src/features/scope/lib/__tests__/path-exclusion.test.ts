import { describe, expect, it } from 'vitest'
import {
  effectiveTesting,
  methodsText,
  pathPrefixProblem,
  pathRuleLabel,
  testingImpact,
  testingProblem,
} from '../path-exclusion'

describe('path exclusions', () => {
  it('labels the rule as host + prefix', () => {
    expect(pathRuleLabel({ host_pattern: '*.acme.io', path_prefix: '/admin' })).toBe(
      '*.acme.io/admin'
    )
    expect(pathRuleLabel({ path_prefix: 'api' })).toBe('*/api')
  })

  it('empty methods block every method', () => {
    expect(methodsText([])).toBe('every method')
    expect(methodsText(['POST', 'DELETE'])).toBe('POST, DELETE')
  })

  it('prefers the mode in force now over the one set', () => {
    expect(effectiveTesting({ testing: 'allowed', testing_effective: 'blocked' })).toBe('blocked')
    expect(effectiveTesting({})).toBe('blocked')
  })

  it('allowed needs an end of at most 90 days; read-only end is optional', () => {
    expect(testingProblem('allowed', null)).toMatch(/end date/)
    expect(testingProblem('allowed', 91)).toMatch(/1 to 90/)
    expect(testingProblem('allowed', 0)).toMatch(/1 to 90/)
    expect(testingProblem('allowed', 30)).toBeNull()
    expect(testingProblem('read_only', null)).toBeNull()
    expect(testingProblem('blocked', null)).toBeNull()
  })

  it('explains the impact and never claims to widen beyond scope', () => {
    expect(testingImpact('blocked', 'read_only', 'x/admin', [])).toMatch(/GET and HEAD/)
    expect(testingImpact('blocked', 'allowed', 'x/admin', [])).toMatch(
      /outside your scope stay refused/
    )
    expect(testingImpact('allowed', 'blocked', 'x/admin', ['POST'])).toMatch(/stop sending/)
    expect(testingImpact('blocked', 'blocked', 'x', [])).toBe('Nothing changes.')
  })

  it('checks the path prefix like the API', () => {
    expect(pathPrefixProblem('')).not.toBeNull()
    expect(pathPrefixProblem('admin')).toMatch(/starts with/)
    expect(pathPrefixProblem('/a/../b')).toMatch(/Dot segments/)
    expect(pathPrefixProblem('/a%2Fb')).toMatch(/Encoded/)
    expect(pathPrefixProblem('/ad*')).toMatch(/whole segment/)
    expect(pathPrefixProblem('/api/*/admin')).toBeNull()
    expect(pathPrefixProblem('/admin')).toBeNull()
  })
})
