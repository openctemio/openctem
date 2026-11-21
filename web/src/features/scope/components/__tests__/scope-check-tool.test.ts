import { describe, expect, it } from 'vitest'
import { checkToolTargets, SCOPE_CHECK_TOOL_MAX } from '../scope-check-tool'
import { scopeFilterCount } from '../scope-list-filters'

describe('checkToolTargets', () => {
  it('reads one target per line (or comma), trimmed and de-duplicated', () => {
    expect(checkToolTargets(' a.example.com \n\nA.example.com, 192.0.2.15\n')).toEqual([
      'a.example.com',
      '192.0.2.15',
    ])
  })
  it('checks at most the cap in one go', () => {
    const many = Array.from({ length: SCOPE_CHECK_TOOL_MAX + 10 }, (_, i) => `h${i}.example.com`)
    expect(checkToolTargets(many.join('\n'))).toHaveLength(SCOPE_CHECK_TOOL_MAX)
  })
})

describe('scopeFilterCount', () => {
  it('counts the applied filters, not the defaults', () => {
    expect(scopeFilterCount('all', 'all')).toBe(0)
    expect(scopeFilterCount('domain', 'all')).toBe(1)
    expect(scopeFilterCount('domain', 'active')).toBe(2)
  })
})
