import { describe, expect, it } from 'vitest'

import {
  formatWindow,
  parseHeaderLines,
  parseWindowLines,
  rulesFromForm,
  shortHash,
  summarizePreview,
} from '../program-form'
import type { ProgramPreview } from '../../api/programs-api.types'

describe('parseHeaderLines', () => {
  it('reads Name: value lines and reports bad ones by number', () => {
    const { headers, invalid } = parseHeaderLines(
      'X-Bug-Bounty: jdoe\n\n: no name\nnot a header\nBad Name: x\nX-Empty:\n'
    )
    expect(headers).toEqual([
      { name: 'X-Bug-Bounty', value: 'jdoe' },
      { name: 'X-Empty', value: '' },
    ])
    expect(invalid).toEqual([3, 4, 5])
  })
})

describe('rulesFromForm', () => {
  it('normalizes the form', () => {
    expect(
      rulesFromForm({
        rateLimit: '5',
        headers: 'X-A: 1',
        userAgent: '  ua  ',
        forbidden: ['physical', 'dos'],
        notes: ' n ',
      })
    ).toEqual({
      rate_limit_rps: 5,
      required_headers: [{ name: 'X-A', value: '1' }],
      user_agent: 'ua',
      forbidden: ['dos', 'physical'],
      notes: 'n',
      testing_windows: [],
    })
  })

  it('treats an empty or invalid rate limit as none stated', () => {
    for (const rateLimit of ['', 'abc', '-3', '0']) {
      expect(
        rulesFromForm({ rateLimit, headers: '', userAgent: '', forbidden: [], notes: '' })
          .rate_limit_rps
      ).toBe(0)
    }
  })
})

describe('summarizePreview', () => {
  it('counts what an import would do', () => {
    const p: ProgramPreview = {
      items: [],
      entries: [
        { target_type: 'domain', pattern: '*.a.example', status: 'create' },
        { target_type: 'domain', pattern: 'b.example', status: 'create' },
        { target_type: 'domain', pattern: 'c.example', status: 'keep' },
        {
          target_type: 'domain',
          pattern: 'd.example',
          status: 'already_covered',
          source: 'ownership',
        },
        { target_type: 'domain', pattern: '*.co.uk', status: 'refused', code: 'PUBLIC_SUFFIX' },
      ],
      exclusions: [
        { target_type: 'domain', pattern: 'a.example', reason: 'apex' },
        {
          target_type: 'domain',
          pattern: 'admin.a.example',
          reason: 'out',
          in_scope_by: { entry_id: '1', pattern: '*.a.example', source: 'ownership' },
        },
      ],
      not_scannable: [{ raw: 'com.app', in_scope: true, kind: 'other' }],
      max_tier: 't1',
      terms_sha256: 'f'.repeat(64),
    }
    expect(summarizePreview(p)).toEqual({
      create: 2,
      keep: 1,
      alreadyCovered: 1,
      refused: 1,
      exclusions: 2,
      overlaps: 1,
      notScannable: 1,
    })
  })
})

describe('shortHash', () => {
  it('shortens a hash', () => {
    expect(shortHash('abcdef0123456789abcdef')).toBe('abcdef012345…')
    expect(shortHash(undefined)).toBe('')
  })
})

describe('parseWindowLines', () => {
  it('reads days, a span and a zone per line', () => {
    const { windows, invalid } = parseWindowLines(
      'mon-fri 09:00-17:00 Europe/Paris\n\nSAT,sun 10:00-12:30 UTC\nfri-mon 08:00-09:00 Asia/Ho_Chi_Minh\n'
    )
    expect(invalid).toEqual([])
    expect(windows).toEqual([
      {
        days: ['mon', 'tue', 'wed', 'thu', 'fri'],
        start: '09:00',
        end: '17:00',
        timezone: 'Europe/Paris',
      },
      { days: ['sun', 'sat'], start: '10:00', end: '12:30', timezone: 'UTC' },
      {
        days: ['sun', 'mon', 'fri', 'sat'],
        start: '08:00',
        end: '09:00',
        timezone: 'Asia/Ho_Chi_Minh',
      },
    ])
  })

  it('reports malformed lines by number', () => {
    const { windows, invalid } = parseWindowLines(
      [
        'mon 09:00-17:00', // no zone
        'funday 09:00-17:00 UTC',
        'mon 17:00-09:00 UTC', // overnight
        'mon 9:00-17:00 UTC',
        'mon 09:00-24:00 UTC',
        'mon 09:00-17:00 UTC extra',
        'mon 09:00-17:00 UTC',
      ].join('\n')
    )
    expect(invalid).toEqual([1, 2, 3, 4, 5, 6])
    expect(windows).toHaveLength(1)
  })

  it('round-trips through formatWindow', () => {
    const w = { days: ['mon', 'wed'] as const, start: '09:00', end: '17:00', timezone: 'UTC' }
    const line = formatWindow({ ...w, days: [...w.days] })
    expect(line).toBe('mon,wed 09:00-17:00 UTC')
    expect(parseWindowLines(line).windows[0]).toEqual({ ...w, days: ['mon', 'wed'] })
  })

  it('goes into the rules', () => {
    expect(
      rulesFromForm({
        rateLimit: '',
        headers: '',
        userAgent: '',
        forbidden: [],
        notes: '',
        windows: 'tue 01:00-02:00 UTC',
      }).testing_windows
    ).toEqual([{ days: ['tue'], start: '01:00', end: '02:00', timezone: 'UTC' }])
  })
})
