import { describe, it, expect } from 'vitest'
import { applySuggestion, suggest, tokenAt } from '../lib/query-complete'
import type { QuerySchemaField } from '../api/use-task-query'

const fields: QuerySchemaField[] = [
  {
    path: 'severity',
    type: 'enum',
    operators: ['=', 'in'],
    enum: ['critical', 'high', 'medium', 'low'],
  },
  { path: 'status', type: 'enum', operators: ['=', 'in'], enum: ['new', 'confirmed'] },
  { path: 'asset.internet_facing', type: 'bool', operators: ['='] },
]

describe('query completion', () => {
  it('finds the word under the caret', () => {
    expect(tokenAt('findings where sev', 18)).toEqual({ word: 'sev', start: 15, end: 18 })
    expect(tokenAt('findings where ', 15).word).toBe('')
  })

  it('suggests fields and keywords by prefix, never the word itself', () => {
    expect(suggest('findings where s', 16, fields)).toEqual(['severity', 'status'])
    expect(suggest('findings w', 10, fields)).toEqual(['where'])
    expect(suggest('findings where severity', 23, fields)).toEqual([])
    expect(suggest('findings where asset.i', 22, fields)).toEqual(['asset.internet_facing'])
  })

  it("suggests the enum values of the clause's field first", () => {
    expect(suggest('findings where severity = c', 27, fields)).toEqual(['critical'])
    expect(suggest('findings where severity in (high, m', 35, fields)).toEqual(['medium'])
  })

  it('replaces only the word at the caret', () => {
    expect(applySuggestion('findings where sev and x', 18, 'severity')).toEqual({
      text: 'findings where severity and x',
      caret: 23,
    })
  })
})
