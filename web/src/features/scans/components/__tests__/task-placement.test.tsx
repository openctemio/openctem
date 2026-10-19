import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'

import { RunTasksTable } from '../run-tasks-table'
import { RunStepPanel } from '../run-step-panel'
import { TaskPlacementPanel, placementSummary, sharedFleetNote } from '../task-placement'
import { enTranslate } from '../../lib/translate'

const getMock = vi.fn()
vi.mock('@/lib/api/client', () => ({ get: (...a: unknown[]) => getMock(...a) }))

const fresh = (ui: React.ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

beforeEach(() => getMock.mockReset())

describe('why a queued task waits', () => {
  it('asks only when opened, then shows the reasons with their fix', async () => {
    getMock.mockResolvedValue({
      queued: true,
      platform: false,
      job_reasons: [],
      evaluated: 3,
      eligible: 0,
      busy: 0,
      truncated: false,
      blocking: [
        { code: 'not_confined', count: 2 },
        { code: 'grant_tools', count: 1 },
      ],
      sensors: [
        { id: 's1', name: 'dmz-1', eligible: false, busy: false, reasons: ['not_confined'] },
      ],
    })
    fresh(
      <RunTasksTable
        runId="r1"
        total={2}
        tasks={[
          { id: 't1', status: 'queued', tool: 'nuclei', targets: 1 },
          {
            id: 't2',
            status: 'queued',
            tool: 'nuclei',
            targets: 1,
            window_hold: { reason: 'closed' } as never,
          },
        ]}
      />
    )
    expect(getMock).not.toHaveBeenCalled()
    // A task that waits for its scan window keeps its window note instead.
    const why = screen.getAllByRole('button', { name: /why waiting/i })
    expect(why).toHaveLength(1)
    await userEvent.click(why[0])
    expect(getMock).toHaveBeenCalledWith('/api/v1/scan-runs/r1/tasks/t1/placement')
    expect(await screen.findByText('None of the 3 sensors can take it:')).toBeInTheDocument()
    const confined = document.querySelector('[data-code="not_confined"]') as HTMLElement
    expect(within(confined).getByText(/seccomp profile/)).toBeInTheDocument()
    expect(within(confined).getByRole('link', { name: 'Open Sensors' })).toHaveAttribute(
      'href',
      '/sensors'
    )
    const grant = document.querySelector('[data-code="grant_tools"]') as HTMLElement
    expect(within(grant).getByText(/\(tools\)/)).toBeInTheDocument()
    expect(screen.getByText('dmz-1')).toBeInTheDocument()
  })

  it('a failed fetch says so', async () => {
    getMock.mockRejectedValueOnce(new Error('placement read failed'))
    fresh(<TaskPlacementPanel runId="r1" taskId="t1" />)
    expect(await screen.findByText(/Could not check/)).toBeInTheDocument()
  })

  it('summarizes each case', () => {
    const t = enTranslate
    expect(placementSummary({ queued: false }, t)).toMatch(/no longer waits/)
    expect(placementSummary({ queued: true, platform: true }, t)).toMatch(/shared sensor/)
    expect(placementSummary({ queued: true, job_reasons: ['window_closed'] }, t)).toMatch(/held/)
    expect(placementSummary({ queued: true, eligible: 2, busy: 2, evaluated: 2 }, t)).toMatch(
      /all busy/
    )
    expect(placementSummary({ queued: true, eligible: 2, busy: 1, evaluated: 3 }, t)).toMatch(
      /2 \(1 busy\)/
    )
    expect(placementSummary({ queued: true, evaluated: 0 }, t)).toMatch(/no sensor/)
  })

  // research/191 W-1: a task nobody of the organization can take says
  // whether the shared sensors were an option.
  it('says whether the shared sensors were an option', () => {
    const t = enTranslate
    expect(sharedFleetNote({ queued: true, evaluated: 0, shared_fleet: 'not_used' }, t)).toMatch(
      /own sensors only/
    )
    expect(sharedFleetNote({ queued: true, evaluated: 1, shared_fleet: 'not_allowed' }, t)).toMatch(
      /not available/
    )
    expect(sharedFleetNote({ queued: true, eligible: 1, shared_fleet: 'not_used' }, t)).toBeNull()
    expect(sharedFleetNote({ queued: true, platform: true }, t)).toBeNull()
  })

  it('says which task holds its hosts instead of "should start shortly"', () => {
    const t = enTranslate
    const base = { queued: true, job_reasons: ['host_busy'], eligible: 1, busy: 0, evaluated: 1 }
    expect(
      placementSummary(
        {
          ...base,
          host_wait: {
            hosts_held: 10,
            hosts_total: 10,
            holders: [{ tool: 'httpx', step_key: 'http', run_id: 'r2', task_id: 'c9' }],
          },
        },
        t
      )
    ).toBe(
      'Waiting: 10 of its 10 hosts are being scanned by httpx (step http). It starts when those hosts are free.'
    )
    // A holder in a run the caller cannot read: the tool only.
    expect(
      placementSummary(
        { ...base, host_wait: { hosts_held: 3, hosts_total: 8, holders: [{ tool: 'naabu' }] } },
        t
      )
    ).toMatch(/3 of its 8 hosts are being scanned by naabu\./)
    expect(
      placementSummary({ ...base, host_wait: { hosts_held: 1, hosts_total: 2, holders: [] } }, t)
    ).toMatch(/by another task/)
    expect(placementSummary({ ...base, host_wait: undefined }, t)).not.toMatch(/shortly/)
    // How many of its targets can start, when known.
    expect(
      placementSummary(
        {
          ...base,
          host_wait: {
            hosts_held: 1,
            hosts_total: 20,
            targets: 23,
            can_start: 21,
            holders: [{ tool: 'nuclei' }],
          },
        },
        t
      )
    ).toBe(
      'Waiting: 1 of its 20 hosts are being scanned by nuclei. It starts when those hosts are free. 21 of its 23 targets are on free hosts.'
    )
  })

  it('links the run that holds its hosts', async () => {
    getMock.mockResolvedValue({
      queued: true,
      job_reasons: ['host_busy'],
      blocking: [],
      host_wait: {
        hosts_held: 2,
        hosts_total: 2,
        holders: [{ tool: 'httpx', step_key: 'http', run_id: 'r2', task_id: 'c9' }],
      },
    })
    fresh(<TaskPlacementPanel runId="r1" taskId="t1" />)
    expect(await screen.findByRole('link', { name: 'Open the run scanning them' })).toHaveAttribute(
      'href',
      '/scans/runs?run=r2'
    )
  })
})

describe('a failed step explains its code', () => {
  it('shows the code, its class, the fix and a link', () => {
    fresh(
      <RunStepPanel
        runId="r1"
        node={{
          step_key: 'templates',
          name: 'Templates',
          state: 'failed',
          reason: 'WEB_SCOPE_UNSUPPORTED',
          error_class: 'placement',
          error_message: 'nuclei keeps to a web scope only in a tool sandbox',
        }}
        tasks={[]}
        onClose={() => {}}
      />
    )
    const help = document.querySelector('[data-code="WEB_SCOPE_UNSUPPORTED"]') as HTMLElement
    expect(within(help).getByText('Placement')).toBeInTheDocument()
    expect(within(help).getByText(/seccomp profile/)).toBeInTheDocument()
    expect(within(help).getByRole('link', { name: 'Open Sensors' })).toBeInTheDocument()
  })

  it('a waiting step shows no error help', () => {
    fresh(
      <RunStepPanel
        runId="r1"
        node={{ step_key: 's', name: 'S', state: 'waiting', reason: 'waiting_for_sensor' }}
        tasks={[]}
        onClose={() => {}}
      />
    )
    expect(document.querySelector('[data-code]')).toBeNull()
  })
})
