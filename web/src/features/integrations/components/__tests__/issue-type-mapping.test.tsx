/**
 * Issue types per kind: one row each for findings, remediation tasks and
 * campaign epics, chosen from the default project's live list (sub-task
 * types hidden), with a suggestion, the mapping state and the last refusal.
 */
import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

const INTG = '0193e7a2-1111-7222-8333-944455556666'

vi.mock('@/features/ticket-mapping/api/use-ticket-mapping-api', () => ({
  useIssueTypes: (_id: string, project: string | undefined) => ({
    data: project
      ? {
          issue_types: [
            { id: '10001', name: 'Bug', subtask: false },
            { id: '10042', name: 'Security Finding', subtask: false },
            { id: '10043', name: 'Remediation Task', subtask: false },
            { id: '10044', name: 'Sub-task', subtask: true },
          ],
        }
      : undefined,
    isLoading: false,
    error: undefined,
  }),
  useMappingProfiles: () => ({
    data: {
      data: [
        {
          id: 'p1',
          integration_id: INTG,
          object_kind: 'finding',
          project_key: 'SEC',
          issue_type_id: '10042',
          published_version: 3,
          drifted: true,
        },
      ],
    },
  }),
}))

import { IssueTypeMapping } from '../issue-type-mapping'

describe('IssueTypeMapping', () => {
  it('asks for a default project first', () => {
    render(<IssueTypeMapping integrationId={INTG} projectKey="" value={{}} onChange={vi.fn()} />)
    expect(screen.getByText(/Choose a default project first/)).toBeInTheDocument()
  })

  it('suggests the custom types and saves id and name', () => {
    const onChange = vi.fn()
    render(
      <IssueTypeMapping integrationId={INTG} projectKey="sec" value={{}} onChange={onChange} />
    )
    fireEvent.click(screen.getByRole('button', { name: /Use Security Finding/ }))
    expect(onChange).toHaveBeenLastCalledWith({
      finding: { id: '10042', name: 'Security Finding' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Use Remediation Task/ }))
    expect(onChange).toHaveBeenLastCalledWith({ task: { id: '10043', name: 'Remediation Task' } })
  })

  it('shows the mapping state, drift, a link to map an unmapped type and the last refusal', () => {
    render(
      <IssueTypeMapping
        integrationId={INTG}
        projectKey="SEC"
        value={{
          finding: { id: '10042', name: 'Security Finding' },
          task: { id: '10043', name: 'Remediation Task' },
        }}
        onChange={vi.fn()}
        health={{ task: { issue_type: 'Remediation Task', fields: ['customfield_10050'] } }}
      />
    )
    expect(screen.getByText('Fields and statuses: mapping v3')).toBeInTheDocument()
    expect(screen.getByText('Jira changed')).toBeInTheDocument()
    const link = screen.getByRole('link', { name: /Map fields and statuses/ })
    expect(link.getAttribute('href')).toBe(
      `/settings/integrations/ticketing/mappings?new=1&integration=${INTG}&kind=task&project=SEC&type=10043`
    )
    expect(
      screen.getByText(/refused the last Remediation Task issue because of: customfield_10050/)
    ).toBeInTheDocument()
  })
})
