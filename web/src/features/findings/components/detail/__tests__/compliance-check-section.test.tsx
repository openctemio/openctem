/**
 * The configuration check panel: the result badge, expected beside actual,
 * the sub-checks failed first and expandable, references grouped by
 * framework with "+N more", and producer text kept as text.
 */

import { describe, it, expect } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { ComplianceCheckSection } from '../compliance-check-section'
import type { ComplianceCheck } from '../../../lib/compliance-check'

const check = (over: Partial<ComplianceCheck> = {}): ComplianceCheck => ({
  outcome: 'FAILED',
  benchmark: 'CIS Example Linux',
  benchmarkVersion: '1.0.0',
  profile: 'Level 1 - Server',
  control: '5.3.2.2',
  auditFile: 'CIS_Example_Linux_L1_v1.0.0.audit',
  policyValue: 'expect: pam_faillock',
  actualValue: 'raw',
  subChecks: [
    {
      outcome: 'FAILED',
      name: 'authfail in password-auth',
      file: '/etc/example/password-auth',
      expect: '^auth\\s+required',
      detail: 'The file does not contain it <script>alert(1)</script>',
    },
    { outcome: 'PASSED', name: 'preauth in system-auth', detail: 'auth required pam_faillock.so' },
  ],
  references: [
    {
      framework: '800-53',
      label: 'NIST SP 800-53',
      ids: ['AC-7', 'AC-6(2)', 'AC-2', 'AC-3', 'AC-4', 'AC-5'],
    },
    { framework: 'CSCv8', label: 'CIS Controls v8', ids: ['6.2'] },
    { framework: 'NESA', label: 'NESA', ids: ['T1.2.1'] },
    { framework: 'CSF', label: 'NIST CSF', ids: ['PR.AC-1'] },
    { framework: 'HIPAA', label: 'HIPAA', ids: ['164.312(a)(1)'] },
  ],
  shownExtraKeys: [],
  ...over,
})

describe('ComplianceCheckSection', () => {
  it('shows the result, the benchmark and the clearly labelled expected value', () => {
    render(<ComplianceCheckSection check={check()} />)
    expect(screen.getByText('Configuration check')).toBeInTheDocument()
    expect(screen.getAllByText('Failed')[0].closest('[data-slot="tone-chip"]')).toHaveAttribute(
      'data-value',
      'FAILED'
    )
    expect(screen.getByText('CIS Example Linux v1.0.0')).toBeInTheDocument()
    expect(screen.getByText('Level 1 - Server')).toBeInTheDocument()
    expect(screen.getByText('5.3.2.2')).toBeInTheDocument()
    expect(screen.getAllByText('Expected (policy) value').length).toBeGreaterThan(0)
    expect(screen.getByText('1 of 2 sub-checks did not pass')).toBeInTheDocument()
  })

  it('lists sub-checks failed first, each opening to its file and match', () => {
    const { container } = render(<ComplianceCheckSection check={check()} />)
    const rows = within(screen.getByRole('list', { name: 'Sub-checks' })).getAllByRole('listitem')
    expect(rows[0]).toHaveTextContent('authfail in password-auth')
    expect(rows[1]).toHaveTextContent('preauth in system-auth')
    const first = container.querySelector('details[data-outcome="FAILED"]') as HTMLDetailsElement
    expect(first.open).toBe(false)
    fireEvent.click(first.querySelector('summary')!)
    expect(within(first).getByText('/etc/example/password-auth')).toBeInTheDocument()
    expect(within(first).getByText('^auth\\s+required')).toBeInTheDocument()
    // Producer text stays text.
    expect(container.querySelector('script')).toBeNull()
    expect(first.textContent).toContain('<script>alert(1)</script>')
  })

  it('groups references by framework, with +N more for ids and frameworks', () => {
    render(<ComplianceCheckSection check={check()} />)
    expect(screen.getByText('NIST SP 800-53')).toBeInTheDocument()
    expect(screen.queryByText('AC-5')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '+2 more' }))
    expect(screen.getByText('AC-5')).toBeInTheDocument()
    expect(screen.queryByText('HIPAA')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '+1 more frameworks' }))
    expect(screen.getByText('HIPAA')).toBeInTheDocument()
  })

  it('shows the raw actual value when there are no sub-checks', () => {
    render(
      <ComplianceCheckSection
        check={check({ subChecks: [], actualValue: 'permitrootlogin yes' })}
      />
    )
    expect(screen.getByLabelText('Actual value')).toHaveTextContent('permitrootlogin yes')
  })

  it('puts expected and actual side by side on wide screens, stacked in the drawer and on phones', () => {
    const { container, rerender } = render(<ComplianceCheckSection check={check()} />)
    const grid = () => container.querySelector('[data-slot="compliance-values"]')!
    expect(grid().className).toContain('grid-cols-1')
    expect(grid().className).toContain('lg:grid-cols-2')
    rerender(<ComplianceCheckSection check={check()} compact />)
    expect(grid().className).not.toContain('lg:grid-cols-2')
  })
})
