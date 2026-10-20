/**
 * Group members keep their real asset type (a subdomain is not a "Host"), and
 * a group finding is open by the findings' open statuses, the set the group's
 * finding count counts.
 */
import { describe, it, expect } from 'vitest'
import { transformApiGroupAsset, transformApiGroupFinding } from '../transformers'

describe('transformApiGroupAsset', () => {
  it('keeps every stored asset type as is', () => {
    for (const type of ['subdomain', 'application', 'ip_address', 'storage', 'domain', 'host']) {
      expect(transformApiGroupAsset({ id: 'a', name: 'n', type }).type).toBe(type)
    }
  })
})

describe('transformApiGroupFinding', () => {
  it('marks open statuses open and closed ones not', () => {
    const open = ['new', 'confirmed', 'in_progress', 'fix_applied']
    const closed = ['resolved', 'false_positive', 'accepted', 'verified']
    for (const status of open) expect(transformApiGroupFinding({ id: 'f', status }).open).toBe(true)
    for (const status of closed)
      expect(transformApiGroupFinding({ id: 'f', status }).open).toBe(false)
  })
})
