import { describe, expect, it } from 'vitest'

import { parseHeaderLines, rulesFromForm, shortHash, summarizePreview } from '../program-form'
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
