import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { Button } from '@/components/ui/button'
import type { DataTableBulk } from '@/features/shared/components/data-table/data-table-selection'
import type { Sensor } from '@/lib/api/sensor-types'
import { TEST_SENSOR_KEY_PREFIX } from '@/test/sensor-keys'

import { SensorTable } from '../sensor-table'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

// What the viewer holds (the API checks each write again).
const perms = vi.hoisted(() => ({ write: true, revoke: true, delete: true }))
vi.mock('../../lib/use-sensor-action-perms', () => ({
  useSensorActionPerms: () => ({ ...perms, bearerKeys: true }),
}))

const NOW = new Date('2026-10-31T03:42:00Z').getTime()

const base: Sensor = {
  id: 's1',
  tenant_id: 't',
  name: 'edge-sensor',
  hostname: 'edge-01.example.com',
  ip_address: '192.0.2.10',
  type: 'worker',
  capabilities: [],
  effective: { tools: ['nuclei', 'httpx', 'subfinder'], capabilities: [], max_concurrent_jobs: 5 },
  execution_mode: 'daemon',
  status: 'active',
  health: 'online',
  api_key_prefix: TEST_SENSOR_KEY_PREFIX,
  cpu_percent: 0,
  memory_percent: 0,
  max_concurrent_jobs: 5,
  current_jobs: 0,
  labels: {},
  config: {},
  metadata: {},
  total_findings: 0,
  total_scans: 0,
  error_count: 0,
  created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-01T00:00:00Z',
  last_seen_at: new Date(NOW - 14_000).toISOString(),
  version: 'v0.29.1',
}

const handlers = {
  onViewSensor: vi.fn(),
  onEditSensor: vi.fn(),
  onActivateSensor: vi.fn(),
  onDeactivateSensor: vi.fn(),
  onDeleteSensor: vi.fn(),
  onRegenerateKey: vi.fn(),
  onRevokeSensor: vi.fn(),
}

function renderTable(sensors: Sensor[], bulk?: DataTableBulk<Sensor>) {
  return render(<SensorTable sensors={sensors} now={NOW} channel={{}} bulk={bulk} {...handlers} />)
}

// Row menus are looked up with `hidden`: a menu a test before left closing
// may still hide the rest of the page from the accessibility tree.
const menuItems = async () => (await screen.findAllByRole('menuitem')).map((i) => i.textContent)

describe('SensorTable', () => {
  beforeEach(() => {
    Object.assign(perms, { write: true, revoke: true, delete: true })
    for (const fn of Object.values(handlers)) fn.mockClear()
  })

  it('names every default column and keeps the host in a column of its own', () => {
    renderTable([base])
    const table = screen.getByRole('table')
    expect(
      within(table)
        .getAllByRole('columnheader')
        .map((h) => h.textContent?.trim())
        .filter(Boolean)
    ).toEqual(['Sensor', 'Host', 'Status', 'Version', 'Jobs', 'Tools', 'Actions'])
    const row = within(table).getAllByRole('row')[1]
    expect(within(row).getByText('edge-sensor')).toHaveAttribute('data-slot', 'sensor-name')
    expect(row.querySelector('[data-slot="sensor-host"]')).toHaveTextContent('edge-01.example.com')
    expect(row.querySelector('[data-slot="sensor-ip"]')).toHaveTextContent('192.0.2.10')
  })

  it('says the reason under the state, whole, and all of it on hover', () => {
    renderTable([
      {
        ...base,
        state: 'degraded',
        health_reasons: [
          { code: 'stopped_claiming', severity: 'critical', message: 'Local storage is full.' },
        ],
        local_store: {
          level: 'high',
          stop_claiming: true,
          reason: '9 % of the volume free, below 15 %',
          total_bytes: 0,
          disk_level: 'ok',
          reported_at: null,
        },
      },
    ])
    const reason = document.querySelector('[data-slot="sensor-reason"]') as HTMLElement
    expect(reason).toHaveTextContent('takes no new jobs: storage full')
    expect(reason).toHaveClass('text-destructive')
    // The reason is the cell's second line: it wraps in full, with no clamp.
    expect(reason).toHaveClass('whitespace-normal')
    const line = reason.closest('[data-slot="stacked-cell-secondary"]')
    expect(line?.className).not.toMatch(/line-clamp|truncate/)
    const cell = reason.closest('[data-slot="sensor-status"]') as HTMLElement
    expect(cell.getAttribute('title')).toContain('Local storage is full.')
    expect(within(cell).getByText('Degraded')).toBeInTheDocument()
  })

  it('shows the heartbeat age under the state of a sensor with nothing to report', () => {
    renderTable([{ ...base, state: 'online', health_reasons: [] }])
    expect(document.querySelector('[data-slot="sensor-reason"]')).toBeNull()
    expect(document.querySelector('[data-slot="sensor-state-detail"]')).toHaveTextContent(
      /heartbeat/
    )
  })

  it('keeps the row menu set and order: view, edit, rotate key, disable, revoke, delete', async () => {
    const user = userEvent.setup()
    renderTable([{ ...base, auth_kind: 'bearer' }])
    await user.click(screen.getByRole('button', { name: 'Actions for edge-sensor', hidden: true }))
    expect(await menuItems()).toEqual([
      'View details',
      'Edit',
      'Rotate key',
      'Disable',
      'Revoke',
      'Delete',
    ])
    // Each item hands the sensor to the page, which owns the confirmation.
    await user.click(screen.getByRole('menuitem', { name: 'Revoke' }))
    expect(handlers.onRevokeSensor).toHaveBeenCalledWith(expect.objectContaining({ id: 's1' }))
    expect(handlers.onDeleteSensor).not.toHaveBeenCalled()
  })

  it('hides every change from a viewer with no sensor permission', async () => {
    Object.assign(perms, { write: false, revoke: false, delete: false })
    renderTable([base])
    // One action left: the shared menu draws it as the row's one button.
    expect(
      screen.queryByRole('button', { name: 'Actions for edge-sensor', hidden: true })
    ).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: /View details/, hidden: true }))
    expect(handlers.onViewSensor).toHaveBeenCalledWith(expect.objectContaining({ id: 's1' }))
    for (const name of ['Edit', 'Rotate key', 'Disable', 'Revoke', 'Delete']) {
      expect(screen.queryByRole('button', { name, hidden: true })).toBeNull()
      expect(screen.queryByRole('menuitem', { name, hidden: true })).toBeNull()
    }
  })

  it('offers Enable, never Disable or Rotate, on a disabled sensor', async () => {
    renderTable([{ ...base, status: 'disabled', auth_kind: 'bearer' }])
    await userEvent.click(
      screen.getByRole('button', { name: 'Actions for edge-sensor', hidden: true })
    )
    const items = await menuItems()
    expect(items).toContain('Enable')
    expect(items).not.toContain('Disable')
  })

  it('has no checkbox column without a bulk action, and names each checkbox with one', () => {
    const { unmount } = renderTable([base])
    expect(screen.queryByRole('checkbox')).toBeNull()
    unmount()
    renderTable([base], {
      rowLabel: (s) => s.name,
      checkboxLabel: (s) => `Select sensor ${s.name}`,
      actions: <Button>Disable</Button>,
    })
    expect(screen.getByRole('checkbox', { name: 'Select sensor edge-sensor' })).toBeInTheDocument()
  })

  it('says no sensor matches, with Clear filters, when a filter leaves no row', async () => {
    const clear = vi.fn()
    render(
      <SensorTable
        sensors={[]}
        now={NOW}
        channel={{}}
        isFiltered
        onClearFilters={clear}
        {...handlers}
      />
    )
    expect(screen.getByText('No sensors match these filters')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(clear).toHaveBeenCalled()
  })

  it('keeps the toolbar and offers Retry when the fleet read fails', async () => {
    const retry = vi.fn()
    render(
      <SensorTable
        sensors={[]}
        now={NOW}
        channel={{}}
        error={{ statusCode: 500 }}
        onRetry={retry}
        search={{ value: '', onChange: vi.fn(), placeholder: 'Search sensors…', label: 'Search' }}
        {...handlers}
      />
    )
    expect(screen.getByPlaceholderText('Search sensors…')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(retry).toHaveBeenCalled()
  })

  it('puts the marks under the name in one look, the most serious first and the rest as +N', () => {
    render(
      <SensorTable
        sensors={[{ ...base, posture: { unhardened: ['policy_none'] } } as Sensor]}
        now={NOW}
        channel={{}}
        grants={
          new Map([['s1', { sensor_id: 's1', legacy_broad: true, trust_level: 'new' } as never]])
        }
        {...handlers}
      />
    )
    const name = document.querySelector('[data-slot="sensor-name-cell"]') as HTMLElement
    // The name on its own line, the marks on the line under it.
    expect(name).toHaveClass('flex-col')
    const flags = name.querySelector('[data-slot="sensor-flags"]') as HTMLElement
    const shown = flags.querySelectorAll('[data-slot="health-status"]')
    expect(shown).toHaveLength(1)
    expect(shown[0]).toHaveAttribute('data-health', 'warn')
    expect(flags.querySelector('[data-slot="sensor-flags-more"]')).toHaveTextContent('+2')
    // Every mark is in the hover text, Passive only included.
    expect(flags.getAttribute('title')).toContain('Passive only')
    expect(flags.getAttribute('title')).toContain('Legacy broad grant')
  })

  it('shows a quiet dash for a host never reported and no bar while no job runs', () => {
    renderTable([{ ...base, hostname: undefined, ip_address: undefined } as unknown as Sensor])
    const none = document.querySelector('[data-slot="sensor-host-none"]') as HTMLElement
    expect(none).toHaveAttribute('title', 'No host reported yet')
    expect(none).toHaveTextContent('—')
    expect(document.querySelector('[data-slot="sensor-jobs-bar"]')).toBeNull()
    expect(screen.getByText('0/5')).toBeInTheDocument()
  })

  it('draws the jobs bar while jobs run', () => {
    renderTable([{ ...base, current_jobs: 2 }])
    expect(document.querySelector('[data-slot="sensor-jobs-bar"]')).not.toBeNull()
  })
})
