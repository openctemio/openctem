import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SWRConfig } from 'swr'

import {
  RunTimeline,
  WAITING_FOR_SENSOR_MS,
  eventActor,
  eventLabel,
  movedSentence,
  tasksWaitingForSensor,
} from '../run-timeline'

const getMock = vi.fn()
vi.mock('@/lib/api/client', () => ({ get: (url: string) => getMock(url) }))

const fresh = (ui: React.ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const at = (msAgo: number) => new Date(Date.now() - msAgo).toISOString()

describe('run timeline helpers', () => {
  it('names each event, and passes an unknown one through', () => {
    expect(eventLabel('requeued')).toBe('Handed back to the queue')
    expect(eventLabel('refused')).toBe('Refused by the sensor')
    expect(eventLabel('something_new')).toBe('something_new')
  })

  it('never names a platform sensor', () => {
    expect(eventActor({ platform: true, sensor_id: 'abcdef1234' })).toBe('Shared sensors')
    expect(eventActor({ platform: false, sensor_id: 'abcdef1234' })).toBe('Sensor abcdef12')
    expect(eventActor({ platform: false })).toBeNull()
  })

  it('finds tasks queued too long without a sensor', () => {
    const events = [
      { id: '1', task_id: 'a', event: 'queued', at: at(WAITING_FOR_SENSOR_MS + 60_000) },
      { id: '2', task_id: 'b', event: 'queued', at: at(WAITING_FOR_SENSOR_MS + 60_000) },
      { id: '3', task_id: 'b', event: 'claimed', at: at(1000) },
      { id: '4', task_id: 'c', event: 'requeued', at: at(1000) },
    ]
    expect(tasksWaitingForSensor(events)).toEqual(['a'])
  })
})

describe('movedSentence', () => {
  const moved = { event: 'requeued', sensor_id: 'abcdef1234', platform: false, attempt: 1 }

  it('explains a move from its code, with the next attempt', () => {
    expect(movedSentence({ ...moved, code: 'moved.tool_crashed' })).toBe(
      'Moved to another sensor: the tool crashed on sensor abcdef12. Attempt 2 of 3.'
    )
    expect(movedSentence({ ...moved, code: 'moved.resource.disk' })).toContain(
      'ran out of disk space'
    )
    expect(movedSentence({ ...moved, code: 'moved.sensor_offline', attempt: 2 })).toContain(
      'Attempt 3 of 3'
    )
  })

  it('has a generic sentence for a reason a newer API sends, and none for other events', () => {
    expect(movedSentence({ ...moved, code: 'moved.something_new' })).toContain(
      'not about the target'
    )
    expect(movedSentence({ ...moved, code: undefined })).toBeNull()
    expect(movedSentence({ ...moved, event: 'failed', code: 'moved.tool_crashed' })).toBeNull()
  })

  it('never names a shared sensor', () => {
    const text = movedSentence({ ...moved, platform: true, code: 'moved.tool_crashed' })
    expect(text).toContain('Shared sensors')
    expect(text).not.toContain('abcdef12')
  })
})

describe('RunTimeline', () => {
  beforeEach(() => getMock.mockReset())

  it('lists the events and explains a task waiting for a sensor', async () => {
    getMock.mockResolvedValue({
      truncated: false,
      events: [
        { id: '1', task_id: 'task-aaaa1111', event: 'queued', at: at(WAITING_FOR_SENSOR_MS * 2) },
        {
          id: '2',
          task_id: 'task-bbbb2222',
          event: 'failed',
          platform: true,
          message: 'scanner exited 2',
          at: at(1000),
        },
      ],
    })
    fresh(<RunTimeline runId="r1" />)
    expect(await screen.findByText('Failed')).toBeInTheDocument()
    expect(screen.getByText('Shared sensors')).toBeInTheDocument()
    expect(screen.getByText(/scanner exited 2/)).toBeInTheDocument()
    expect(screen.getByText(/Waiting for a sensor: 1 task/)).toBeInTheDocument()
    expect(getMock).toHaveBeenCalledWith('/api/v1/scan-runs/r1/events')
  })

  it('puts time, task and actor on one metadata line', async () => {
    getMock.mockResolvedValue({
      truncated: false,
      events: [
        { id: '1', task_id: 'task-aaaa1111', event: 'claimed', platform: true, at: at(5000) },
      ],
    })
    const { container } = fresh(<RunTimeline runId="r3" />)
    await screen.findByText('Shared sensors')
    const line = container.querySelector('[data-slot="meta-line"]')
    expect(line).not.toBeNull()
    expect(line).toHaveTextContent('Shared sensors')
  })

  it('says when there is nothing yet', async () => {
    getMock.mockResolvedValue({ truncated: false, events: [] })
    fresh(<RunTimeline runId="r2" />)
    expect(await screen.findByText(/No task events yet/)).toBeInTheDocument()
  })
})
