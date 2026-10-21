import { describe, expect, it } from 'vitest'
import {
  issueTypesForSave,
  readIssueTypes,
  readTicketingHealth,
  suggestIssueType,
} from '../issue-types'

const types = [
  { id: '10001', name: 'Bug' },
  { id: '10002', name: 'Task' },
  { id: '10042', name: 'Security Finding' },
  { id: '10043', name: 'Remediation Task' },
  { id: '10000', name: 'Epic' },
]

describe('issue types per kind', () => {
  it('suggests the custom security types before the stock ones', () => {
    expect(suggestIssueType('finding', types)?.id).toBe('10042')
    expect(suggestIssueType('task', types)?.id).toBe('10043')
    expect(suggestIssueType('epic', types)?.id).toBe('10000')
    expect(suggestIssueType('finding', [{ id: '1', name: 'Bug' }])?.id).toBe('1')
    expect(suggestIssueType('task', [{ id: '1', name: 'Story' }])).toBeUndefined()
  })

  it('reads only well-formed entries and drops a malformed id', () => {
    expect(
      readIssueTypes({
        issue_types: {
          finding: { id: '10042', name: 'Security Finding' },
          task: { id: '10043;x', name: 'Remediation Task' },
          epic: 'Epic',
          risk: { id: '1', name: 'Risk' },
        },
      })
    ).toEqual({
      finding: { id: '10042', name: 'Security Finding' },
      task: { id: '', name: 'Remediation Task' },
    })
    expect(readIssueTypes(undefined)).toEqual({})
  })

  it('saves only chosen kinds', () => {
    expect(issueTypesForSave({ task: { id: '10043', name: 'Remediation Task' } })).toEqual({
      task: { id: '10043', name: 'Remediation Task' },
    })
    expect(issueTypesForSave({})).toEqual({})
  })

  it('reads the ticketing health per kind', () => {
    expect(
      readTicketingHealth({
        ticketing_health: {
          task: { issue_type: 'Remediation Task', fields: ['customfield_1', 3] },
        },
      })
    ).toEqual({ task: { issue_type: 'Remediation Task', fields: ['customfield_1'] } })
    expect(readTicketingHealth({})).toEqual({})
  })
})
