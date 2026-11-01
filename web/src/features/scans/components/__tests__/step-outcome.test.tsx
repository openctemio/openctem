import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

vi.mock('@/lib/api/client', () => ({ get: vi.fn() }))

import { StepOutcome } from '../code-help'
import { RunStepPanel } from '../run-step-panel'

const SUMMARY =
  'Completed with 2 host(s) not fully covered: a.example.com (rate_floor), b.example.com:443 (breaker_open)'

describe('StepOutcome', () => {
  it('lists each host with a translated reason and why', () => {
    render(
      <StepOutcome
        outcome={{
          coverage_gap_count: 3,
          coverage_gaps: [
            { host: 'a.example.com', reason: 'rate_floor' },
            { host: 'b.example.com:443', reason: 'breaker_open' },
          ],
          unfinished_target_count: 1,
        }}
      />
    )
    expect(screen.getByText('3 hosts not fully covered')).toBeInTheDocument()
    expect(screen.getByText('a.example.com')).toBeInTheDocument()
    expect(screen.getByText('kept rate-limiting the scan')).toBeInTheDocument()
    expect(
      screen.getByText(/failed the scanner's requests \(no answer, or connections reset\)/)
    ).toBeInTheDocument()
    expect(screen.getByText('and 1 more host, listed on the tasks')).toBeInTheDocument()
    expect(screen.getByText('1 target not finished')).toBeInTheDocument()
    // The raw reason codes never show.
    expect(screen.queryByText(/rate_floor|breaker_open/)).toBeNull()
  })

  it('a rechecked host says what it did, what its certificate shows and how to fix it', () => {
    render(
      <StepOutcome
        outcome={{
          coverage_gap_count: 2,
          coverage_gaps: [
            {
              host: 'shop.example.com:443',
              reason: 'breaker_open',
              cause: 'http_reset',
              cert: 'expired',
            },
            { host: 'old.example.com:443', reason: 'breaker_open', cause: 'no_answer' },
          ],
        }}
      />
    )
    expect(screen.getByText('TLS answers, resets every HTTP request')).toBeInTheDocument()
    expect(
      screen.getByText(/certificate has expired: browsers refuse the site/)
    ).toBeInTheDocument()
    const link = screen.getByRole('link', { name: 'Open scanner addresses' })
    expect(link).toHaveAttribute('href', '/settings/scanning/proxies#scanner-addresses')
    expect(screen.getByText('no answer')).toBeInTheDocument()
    expect(screen.queryByText(/stopped answering/)).toBeNull()
    expect(screen.queryByText(/http_reset|no_answer|breaker_open/)).toBeNull()
  })

  it('an unknown reason reads as a generic gap', () => {
    render(
      <StepOutcome
        outcome={{
          coverage_gap_count: 1,
          coverage_gaps: [{ host: 'c.example.com', reason: 'new_reason' }],
        }}
      />
    )
    expect(screen.getByText('not fully covered')).toBeInTheDocument()
    expect(screen.queryByText('new_reason')).toBeNull()
  })

  it('nothing to say renders nothing', () => {
    const { container } = render(<StepOutcome outcome={undefined} />)
    expect(container).toBeEmptyDOMElement()
  })
})

describe('RunStepPanel with COVERAGE_GAPS', () => {
  it('explains the code and lists the hosts instead of the English summary', () => {
    render(
      <RunStepPanel
        runId="r1"
        onClose={() => {}}
        node={
          {
            step_key: 'nuclei',
            name: 'Vulnerability scan',
            state: 'partial',
            reason: 'COVERAGE_GAPS',
            error_class: 'partial',
            error_message: SUMMARY,
            depends_on: [],
            findings: 0,
            outcome: {
              coverage_gap_count: 2,
              coverage_gaps: [{ host: 'a.example.com', reason: 'rate_floor' }],
            },
          } as never
        }
      />
    )
    expect(screen.queryByText(/does not describe it yet/)).toBeNull()
    expect(screen.queryByText(SUMMARY)).toBeNull()
    expect(screen.getByText('Partial')).toBeInTheDocument()
    expect(screen.getByText('a.example.com')).toBeInTheDocument()
  })

  it('shows the sensor text for a tool failure', () => {
    render(
      <RunStepPanel
        runId="r1"
        onClose={() => {}}
        node={
          {
            step_key: 's',
            state: 'failed',
            reason: 'TOOL_EXIT',
            error_message: 'nuclei exited with 2',
            depends_on: [],
            findings: 0,
          } as never
        }
      />
    )
    expect(screen.getByText('Message from the sensor')).toBeInTheDocument()
    expect(screen.getByText('nuclei exited with 2')).toBeInTheDocument()
  })
})
