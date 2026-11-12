import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import type { StepRun } from '@/lib/api/scan-workflow-types'
import { RunSentWith, stepsWithSentWith } from '../run-sent-with'

const step = (over: Partial<StepRun>): StepRun => ({
  id: 's1',
  step_key: 'vuln',
  status: 'completed',
  findings_count: 0,
  attempt: 1,
  max_attempts: 1,
  ...over,
})

describe('RunSentWith', () => {
  it('lists only steps whose sensor reported what was sent', () => {
    const steps = [
      step({ id: 'a' }),
      step({ id: 'b', sensor_settings: { sent_with: [{ tool: 'nuclei' }] } }),
    ]
    expect(stepsWithSentWith(steps).map((s) => s.id)).toEqual(['b'])
    expect(stepsWithSentWith(undefined)).toEqual([])
  })

  it('shows the User-Agent rotation, headers with source and not-sent reasons, and the query', () => {
    render(
      <RunSentWith
        steps={[
          step({
            step_name: 'Vulnerability scan',
            sensor_settings: {
              sent_with: [
                {
                  tool: 'nuclei',
                  user_agent: 'scanner/2',
                  user_agent_source: 'job_locked',
                  user_agent_pool: 3,
                  required: true,
                  carrier: 'forwarder',
                  headers: [
                    { name: 'X-Scan', value: 'corp', source: 'job', applied: true },
                    {
                      name: 'X-Local',
                      value: 'mine',
                      source: 'sensor',
                      applied: false,
                      reason: 'locked by the job',
                    },
                  ],
                  query: { name: 'scan', value: 'corp-1', applied: true },
                },
              ],
            },
          }),
        ]}
      />
    )
    expect(screen.getByText('Vulnerability scan')).toBeInTheDocument()
    expect(screen.getByText('scanner/2')).toBeInTheDocument()
    expect(screen.getByText(/Rotating over 3 values/)).toBeInTheDocument()
    expect(screen.getByText('Identification required')).toBeInTheDocument()
    expect(screen.getByText('Added by the sensor forwarder')).toBeInTheDocument()
    expect(screen.getByText('X-Scan: corp')).toBeInTheDocument()
    expect(screen.getByText(/Not sent: locked by the job/)).toBeInTheDocument()
    expect(screen.getByText('?scan=corp-1')).toBeInTheDocument()
  })
})
