import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ApiClientError } from '@/lib/api/error-handler'

import type { FreezeWindow } from '../types'

// Radix Switch measures itself; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const perms = vi.hoisted(() => ({ granted: new Set<string>() }))
const api = vi.hoisted(() => ({
  list: [] as unknown[],
  filters: [] as unknown[],
  createFreezeWindow: vi.fn(),
  updateFreezeWindow: vi.fn(),
  deleteFreezeWindow: vi.fn(),
  invalidateFreezeWindowsCache: vi.fn(async () => undefined),
}))

vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: (p: string) => perms.granted.has(p) }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('../api/use-freeze-windows', async (importOriginal) => ({
  freezeWindowsURL: (await importOriginal<typeof import('../api/use-freeze-windows')>())
    .freezeWindowsURL,
  createFreezeWindow: api.createFreezeWindow,
  updateFreezeWindow: api.updateFreezeWindow,
  deleteFreezeWindow: api.deleteFreezeWindow,
  invalidateFreezeWindowsCache: api.invalidateFreezeWindowsCache,
  useFreezeWindows: (filter: unknown, enabled = true) => {
    api.filters.push({ filter, enabled })
    return {
      data: enabled ? { data: api.list, total: api.list.length } : undefined,
      error: undefined,
      isLoading: false,
      mutate: vi.fn(),
    }
  },
}))

import { FreezeBanner } from '../components/freeze-banner'
import { FreezeWindowDialog, freezeFormErrors } from '../components/freeze-window-dialog'
import { FreezeWindowsPanel } from '../components/freeze-windows-panel'
import { freezeWindowsURL } from '../api/use-freeze-windows'
import { isFreezeRefusal } from '../lib/errors'
import {
  describeDays,
  describeSchedule,
  endsNextDay,
  utcToZonedLocal,
  zonedLocalToUtc,
} from '../lib/schedule'

const weekly: FreezeWindow = {
  id: 'w1',
  name: 'Patch night',
  description: '',
  timezone: 'Europe/Berlin',
  recurrence: 'weekly',
  days: [6, 7],
  start_time: '22:00',
  end_time: '06:00',
  enabled: true,
  active: false,
  scan_zone_id: undefined,
  created_at: '',
  updated_at: '',
}

beforeEach(() => {
  perms.granted = new Set()
  api.list = []
  api.filters = []
  vi.clearAllMocks()
})

describe('schedule helpers', () => {
  it('converts wall clock in a time zone to instants, across DST', () => {
    // Summer (CEST, UTC+2) and winter (CET, UTC+1) in Berlin.
    expect(zonedLocalToUtc('2026-07-18T22:00', 'Europe/Berlin')?.toISOString()).toBe(
      '2026-07-18T20:00:00.000Z'
    )
    expect(zonedLocalToUtc('2026-12-19T22:00', 'Europe/Berlin')?.toISOString()).toBe(
      '2026-12-19T21:00:00.000Z'
    )
    // 02:30 does not exist on 2026-03-29 in Berlin: the instant after the jump.
    expect(zonedLocalToUtc('2026-03-29T02:30', 'Europe/Berlin')?.toISOString()).toBe(
      '2026-03-29T01:30:00.000Z'
    )
    expect(utcToZonedLocal('2026-07-18T20:00:00Z', 'Europe/Berlin')).toBe('2026-07-18T22:00')
    // 02:30 happens twice on 2026-10-25 in Berlin: the first pass (CEST).
    expect(zonedLocalToUtc('2026-10-25T02:30', 'Europe/Berlin')?.toISOString()).toBe(
      '2026-10-25T00:30:00.000Z'
    )
    expect(zonedLocalToUtc('not a date', 'UTC')).toBeNull()
  })

  it('describes days and overnight windows', () => {
    expect(describeDays([1, 2, 3, 4, 5])).toBe('Weekdays')
    expect(describeDays([7, 6])).toBe('Weekends')
    expect(describeDays([1, 3])).toBe('Mon, Wed')
    expect(endsNextDay('22:00', '06:00')).toBe(true)
    expect(endsNextDay('01:00', '03:00')).toBe(false)
    expect(describeSchedule(weekly)).toBe('Weekends 22:00–06:00 (next day) Europe/Berlin')
  })

  it('builds list URLs for a zone or the organization', () => {
    expect(freezeWindowsURL()).toBe('/api/v1/scan-freeze-windows')
    expect(freezeWindowsURL({ zoneId: 'z1' })).toBe('/api/v1/scan-freeze-windows?scan_zone_id=z1')
    expect(freezeWindowsURL({ tenantWide: true })).toBe('/api/v1/scan-freeze-windows?scope=tenant')
  })

  it('recognises a freeze refusal', () => {
    expect(isFreezeRefusal(new ApiClientError('frozen', 'SCAN_FREEZE_ACTIVE', 409))).toBe(true)
    expect(isFreezeRefusal(new ApiClientError('other', 'CONFLICT', 409))).toBe(false)
    expect(isFreezeRefusal(new Error('x'))).toBe(false)
  })
})

describe('freeze window form', () => {
  const base = {
    name: 'n',
    description: '',
    recurrence: 'once' as const,
    timezone: 'UTC',
    startsLocal: '2026-10-10T22:00',
    endsLocal: '2026-10-11T02:00',
    days: [],
    startTime: '',
    endTime: '',
    now: new Date('2026-10-05T00:00:00Z'),
    creating: true,
  }

  it('accepts a valid one-off window and refuses bad ones', () => {
    expect(freezeFormErrors(base)).toEqual({})
    expect(freezeFormErrors({ ...base, name: ' ' }).name).toBeDefined()
    expect(freezeFormErrors({ ...base, endsLocal: '2026-10-10T21:00' }).ends).toMatch(/after/)
    expect(freezeFormErrors({ ...base, endsLocal: '2026-11-20T00:00' }).ends).toMatch(/31 days/)
    expect(
      freezeFormErrors({ ...base, endsLocal: '2026-10-01T00:00', startsLocal: '2026-09-30T00:00' })
        .ends
    ).toMatch(/already ended/)
  })

  it('needs days and times for a weekly window', () => {
    const w = { ...base, recurrence: 'weekly' as const }
    expect(Object.keys(freezeFormErrors(w)).sort()).toEqual(['days', 'endTime', 'startTime'])
    expect(freezeFormErrors({ ...w, days: [1], startTime: '22:00', endTime: '06:00' })).toEqual({})
  })

  it('sends a new zone window with its zone and the times as entered', async () => {
    api.createFreezeWindow.mockResolvedValue({ id: 'new' })
    render(<FreezeWindowDialog open onOpenChange={vi.fn()} zoneId="z1" zoneName="DC" />)
    await userEvent.type(screen.getByLabelText('Name'), 'Patching')
    await userEvent.click(screen.getByRole('button', { name: 'Create window' }))
    expect(api.createFreezeWindow).toHaveBeenCalledTimes(1)
    const body = api.createFreezeWindow.mock.calls[0][0]
    expect(body).toMatchObject({
      name: 'Patching',
      scan_zone_id: 'z1',
      recurrence: 'weekly',
      days: [6, 7],
      start_time: '22:00',
      end_time: '06:00',
      enabled: true,
    })
    expect(screen.getByTestId('freeze-next-day')).toBeInTheDocument()
  })
})

describe('FreezeBanner', () => {
  it('is hidden when no window is active', () => {
    perms.granted.add('scans:read')
    api.list = [weekly]
    const { container } = render(<FreezeBanner />)
    expect(container).toBeEmptyDOMElement()
  })

  it('names the active windows and their end', () => {
    perms.granted.add('scans:read')
    api.list = [
      { ...weekly, active: true, active_until: '2026-07-19T04:00:00Z' },
      { ...weekly, id: 'w2', name: 'DC freeze', scan_zone_id: 'z9', active: true },
    ]
    render(<FreezeBanner zoneNames={new Map([['z9', 'DC-9']])} />)
    const banner = screen.getByTestId('freeze-banner')
    expect(banner).toHaveTextContent('Patch night freezes the whole organization until')
    expect(banner).toHaveTextContent('DC freeze freezes zone "DC-9"')
  })

  it('on a zone shows that zone and organization-wide windows only', () => {
    perms.granted.add('scans:read')
    api.list = [{ ...weekly, id: 'w2', name: 'Other zone', scan_zone_id: 'z2', active: true }]
    const { container } = render(<FreezeBanner zoneId="z1" />)
    expect(container).toBeEmptyDOMElement()
  })

  it('makes no request without scans:read', () => {
    api.list = [{ ...weekly, active: true }]
    const { container } = render(<FreezeBanner />)
    expect(container).toBeEmptyDOMElement()
    expect(api.filters.every((f) => (f as { enabled: boolean }).enabled === false)).toBe(true)
  })
})

describe('FreezeWindowsPanel', () => {
  it('lists the windows and disables changes for a reader', () => {
    api.list = [{ ...weekly, active: true, active_until: '2026-07-19T04:00:00Z' }]
    render(<FreezeWindowsPanel />)
    expect(screen.getByText('Patch night')).toBeInTheDocument()
    expect(screen.getByText(/^Active until/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Add freeze window/ })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Edit' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Delete Patch night' })).toBeDisabled()
  })

  it('asks for the zone windows or the organization-wide ones', () => {
    render(<FreezeWindowsPanel zoneId="z1" />)
    render(<FreezeWindowsPanel />)
    expect(api.filters).toContainEqual({ filter: { zoneId: 'z1' }, enabled: true })
    expect(api.filters).toContainEqual({ filter: { tenantWide: true }, enabled: true })
  })

  it('deletes after confirmation for an administrator', async () => {
    perms.granted = new Set(['sensors:zones:write', 'sensors:zones:delete'])
    api.list = [weekly]
    api.deleteFreezeWindow.mockResolvedValue(undefined)
    render(<FreezeWindowsPanel />)
    await userEvent.click(screen.getByRole('button', { name: 'Delete Patch night' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Delete' }))
    expect(api.deleteFreezeWindow).toHaveBeenCalledWith('w1')
  })
})
