import { describe, expect, it } from 'vitest'
import { groupTargets } from '../target-groups'
import { parsePastedTargets } from '../target-format'

const typed = (lines: string[]) => parsePastedTargets(lines).lines

describe('groupTargets', () => {
  it('groups by kind in display order, each entry once, invalid entries left out', () => {
    const groups = groupTargets({
      typed: typed([
        '203.0.113.0/24',
        'example.com',
        '*.example.org',
        'https://app.example.com',
        '198.51.100.7',
        'example.com',
        'not a target!',
      ]),
      coverage: 'host',
      assets: [{ id: 'a1', name: 'db.example.com' }],
      groups: [{ id: 'g1', name: 'Web' }],
    })
    expect(groups.map((g) => g.kind)).toEqual([
      'domains',
      'wildcards',
      'ranges',
      'addresses',
      'urls',
      'assets',
      'groups',
    ])
    expect(groups[0].rows).toHaveLength(1)
    expect(groups[0].rows[0].checkAs).toBe('example.com')
    // A group has no scope answer before the run.
    expect(groups[6].rows[0].checkAs).toBeUndefined()
  })

  it('checks a domain as its wildcard when the coverage level widens it', () => {
    const [domains] = groupTargets({
      typed: typed(['example.com']),
      coverage: 'subdomains',
      assets: [],
      groups: [],
    })
    expect(domains.rows[0]).toMatchObject({
      label: 'example.com',
      checkAs: '*.example.com',
      scannedAs: '*.example.com',
    })
  })

  it('lists the addresses a coverage level adds, marked as added', () => {
    const groups = groupTargets({
      typed: typed(['example.com', '198.51.100.7']),
      coverage: 'subdomains_ips',
      assets: [],
      groups: [],
      addedAddresses: ['198.51.100.7', '198.51.100.8'],
    })
    const addresses = groups.find((g) => g.kind === 'addresses')
    expect(addresses?.rows.map((r) => [r.label, !!r.added])).toEqual([
      ['198.51.100.7', false],
      ['198.51.100.8', true],
    ])
  })

  it('is empty for nothing', () => {
    expect(groupTargets({ typed: [], coverage: 'host', assets: [], groups: [] })).toEqual([])
  })
})
