import { describe, expect, it } from 'vitest'
import { queryTokens } from '../lib/highlight'

const kinds = (text: string) =>
  queryTokens(text)
    .filter((t) => t.type !== 'text')
    .map((t) => `${t.type}:${t.value}`)

describe('queryTokens (editor colours, read in the browser)', () => {
  it('gives back the text exactly', () => {
    for (const text of [
      'findings where informational = false and practice != compliance and state = open and status not in (draft, in_review)',
      'severity>=high kev=true -status:accepted title~"a (b" ',
      'practice!=compliance state=fixed\n  OR (port>=1)',
    ])
      expect(
        queryTokens(text)
          .map((t) => t.value)
          .join('')
      ).toBe(text)
  })
  it('tells fields, operators, keywords and values apart', () => {
    expect(kinds('practice!=compliance -status:accepted OR tool="nuclei x"')).toEqual([
      'function:practice',
      'operator:!=',
      'type:compliance',
      'operator:-',
      'function:status',
      'operator::',
      'type:accepted',
      'keyword:OR',
      'function:tool',
      'operator:=',
      'string:"nuclei x"',
    ])
    expect(kinds('findings where status not in (draft, in_review)')).toEqual([
      'keyword:findings',
      'keyword:where',
      'function:status',
      'keyword:not',
      'keyword:in',
      'punctuation:(',
      'type:draft',
      'punctuation:,',
      'type:in_review',
      'punctuation:)',
    ])
  })
})
