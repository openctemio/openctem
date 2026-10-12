import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SWRConfig } from 'swr'

import {
  RunTimeline,
  WAITING_FOR_SENSOR_MS,
  eventActor,
  eventLabel,
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
    expect(eventActor({ platform: true, sensor_id: 'abcdef1234' })).toBe('Platform scanning')
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
    expect(screen.getByText('Platform scanning')).toBeInTheDocument()
    expect(screen.getByText(/scanner exited 2/)).toBeInTheDocument()
    expect(screen.getByText(/Waiting for a sensor: 1 task/)).toBeInTheDocument()
    expect(getMock).toHaveBeenCalledWith('/api/v1/scan-runs/r1/events')
  })

  it('says when there is nothing yet', async () => {
    getMock.mockResolvedValue({ truncated: false, events: [] })
    fresh(<RunTimeline runId="r2" />)
    expect(await screen.findByText(/No task events yet/)).toBeInTheDocument()
  })
})
