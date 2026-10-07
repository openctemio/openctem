import { describe, expect, it } from 'vitest'

import {
  firstWildcard,
  namesMatchingWildcard,
  replaceWildcard,
  scannerTakesWildcard,
  wildcardRoot,
} from '../wildcard-targets'

describe('wildcard targets', () => {
  it('finds the pattern and its root', () => {
    expect(firstWildcard(['a.example.com', ' *.Example.com '])).toBe('*.Example.com')
    expect(firstWildcard(['example.com'])).toBeNull()
    expect(wildcardRoot('*.Example.COM')).toBe('example.com')
  })

  it('only discovery tools take a pattern', () => {
    expect(scannerTakesWildcard('subfinder')).toBe(true)
    expect(scannerTakesWildcard('nuclei')).toBe(false)
    expect(scannerTakesWildcard(undefined)).toBe(false)
  })

  it('matches the root and names under it, not look-alikes', () => {
    expect(
      namesMatchingWildcard(
        [
          'example.com',
          'api.example.com',
          'API.example.com',
          'badexample.com',
          'example.com.evil.io',
        ],
        '*.example.com'
      )
    ).toEqual(['example.com', 'api.example.com'])
  })

  it('replaces the pattern in place, without duplicates', () => {
    expect(
      replaceWildcard(['1.2.3.4', '*.example.com', 'api.example.com'], '*.example.com', [
        'api.example.com',
        'www.example.com',
      ])
    ).toEqual(['1.2.3.4', 'api.example.com', 'www.example.com'])
  })
})
