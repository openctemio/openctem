import { describe, expect, it } from 'vitest'

import type { SensorConfigCheck } from '@/lib/api/sensor-types'

import {
  countParts,
  defaultFixFormat,
  fixFormats,
  groupChecks,
  safeDocsHref,
} from '../config-report'

const c = (id: string, group: string, status: string): SensorConfigCheck => ({
  id,
  group,
  status,
  severity: 'warning',
  code: 'x',
  known: true,
  title: id,
})

describe('groupChecks', () => {
  it('puts the group with the worst check first, then catalog order, checks by status then id', () => {
    const groups = groupChecks([
      c('platform.tls', 'platform', 'pass'),
      c('tools.available', 'tools', 'pass'),
      c('tool.semgrep.binary', 'tools', 'fail'),
      c('identity.state_persistent', 'identity', 'warn'),
      c('x.y', 'made_up', 'error'),
    ])
    expect(groups.map((g) => g.group)).toEqual(['tools', 'other', 'identity', 'platform'])
    expect(groups[0].checks.map((x) => x.id)).toEqual(['tool.semgrep.binary', 'tools.available'])
    expect(groups[1].label).toBe('Other')
  })
})

describe('fix formats', () => {
  it('keeps only known, non-empty string formats in tab order', () => {
    expect(
      fixFormats({ helm: 'a', env: ' ', compose: 'b', script: 'curl x | sh' } as Record<
        string,
        string
      >)
    ).toEqual(['compose', 'helm'])
    expect(fixFormats(undefined)).toEqual([])
    expect(fixFormats({})).toEqual([])
  })

  it('prefers the format matching the runtime', () => {
    expect(defaultFixFormat(['compose', 'helm'], 'kubernetes')).toBe('helm')
    expect(defaultFixFormat(['compose', 'helm'], 'docker')).toBe('compose')
    expect(defaultFixFormat(['helm', 'env'], 'unknown')).toBe('helm')
    expect(defaultFixFormat([], 'docker')).toBeUndefined()
  })
})

describe('safeDocsHref', () => {
  it.each([
    ['https://docs.openctem.io/sensor/settings#X', 'https://docs.openctem.io/sensor/settings#X'],
    ['/docs/sensor', '/docs/sensor'],
  ])('allows %s', (url, want) => {
    expect(safeDocsHref(url)).toBe(want)
  })

  it.each([
    undefined,
    '',
    'https://docs.openctem.io',
    'https://docs.openctem.io.evil.example/',
    'https://docs.openctem.io@evil.example/',
    'https://u:p@docs.openctem.io/x',
    'https://docs.openctem.io:8443/x',
    'http://docs.openctem.io/x',
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    '//evil.example',
    '/\\evil.example',
    '#top',
    'sensor/troubleshooting',
    'https://docs.openctem.io/‮evil',
  ])('refuses %s', (url) => {
    expect(safeDocsHref(url)).toBeNull()
  })
})

describe('countParts', () => {
  it('leaves out zero counts except passed', () => {
    expect(countParts({ pass: 0, warn: 2, fail: 1 })).toEqual([
      { status: 'fail', n: 1 },
      { status: 'warn', n: 2 },
      { status: 'pass', n: 0 },
    ])
  })
})
