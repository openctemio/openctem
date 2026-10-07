import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { ToolAvailabilityItem, ToolAvailabilityResponse } from '@/lib/api/tool-types'
import { ToolsSection } from '../tools-section'

/**
 * The Tools page lists what the sensors report (api tool-availability.md):
 * by default the tools on at least one sensor, with the full catalog behind
 * a switch; status, sensors and versions per tool; status metrics.
 */

const urlState = new Map<string, string>()
const enable = vi.fn()
const disable = vi.fn()
let availability: ToolAvailabilityResponse | undefined

vi.mock('@/hooks/use-url-param', async () => {
  const React = await import('react')
  return {
    useUrlFilter: (key: string, fallback: string) => {
      const [, force] = React.useReducer((n: number) => n + 1, 0)
      return [
        urlState.get(key) ?? fallback,
        (next: string) => {
          if (next === fallback || next === '') urlState.delete(key)
          else urlState.set(key, next)
          force()
        },
      ]
    },
  }
})
vi.mock('@/lib/permissions', () => ({
  Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  useCanMutate: () => true,
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('../add-tool-dialog', () => ({ AddToolDialog: () => null }))
vi.mock('@/lib/api/tool-category-hooks', () => ({
  useAllToolCategories: () => ({ data: { items: [] } }),
  getCategoryNameById: () => '',
  getCategoryDisplayNameById: () => '',
}))
vi.mock('@/lib/api/tool-hooks', () => ({
  useToolAvailability: () => ({
    data: availability,
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
  useDeleteCustomTool: () => ({ trigger: vi.fn(), isMutating: false }),
  useEnableTool: () => ({ trigger: enable }),
  useDisableTool: () => ({ trigger: disable }),
  invalidateToolsCache: vi.fn(),
}))

const catalogTool = (name: string, display: string) =>
  ({
    id: `id-${name}`,
    name,
    display_name: display,
    install_method: 'go',
    has_update: false,
    capabilities: [],
    supported_targets: [],
    output_formats: [],
    is_active: true,
    is_builtin: true,
    is_platform_tool: true,
    tags: [],
    created_at: '2026-10-01T00:00:00Z',
    updated_at: '2026-10-01T00:00:00Z',
  }) as unknown as ToolAvailabilityItem['tool']

function item(over: Partial<ToolAvailabilityItem>): ToolAvailabilityItem {
  return {
    name: 'x',
    tool: null,
    in_catalog: true,
    enabled: true,
    status: 'no_sensor',
    sensors_online: 0,
    sensors_total: 0,
    sensors_excluded: 0,
    sensors: [],
    versions: [],
    update_available: false,
    content: [],
    ...over,
  }
}

const nuclei = item({
  name: 'nuclei',
  tool: catalogTool('nuclei', 'Nuclei'),
  status: 'ready',
  sensors_online: 1,
  sensors_total: 2,
  min_reported_version: 'v3.3.0',
  max_reported_version: 'v3.4.2',
  latest_version: 'v3.4.2',
  update_available: true,
  sensors: [
    { id: 's1', name: 'edge-1', state: 'online', online: true, zones: [{ id: 'z', name: 'dmz' }] },
    { id: 's2', name: 'edge-2', state: 'offline', online: false, zones: [] },
  ],
})
const checkov = item({ name: 'checkov', tool: catalogTool('checkov', 'Checkov') })
const semgrep = item({
  name: 'semgrep',
  tool: catalogTool('semgrep', 'Semgrep'),
  status: 'offline_only',
  sensors_total: 1,
})

describe('ToolsSection', () => {
  beforeEach(() => {
    urlState.clear()
    enable.mockReset()
    disable.mockReset()
    availability = {
      items: [checkov, nuclei, semgrep],
      summary: { ready: 1, no_sensor: 1, offline_only: 1, outdated: 0, disabled: 0 },
      computed_at: '2026-10-07T00:00:00Z',
    }
  })

  it('lists only the tools on a sensor by default, with status, sensors and versions', () => {
    render(<ToolsSection />)
    const table = screen.getByRole('table')
    expect(within(table).getByText('Nuclei')).toBeInTheDocument()
    expect(within(table).getByText('Semgrep')).toBeInTheDocument()
    // No sensor has checkov: hidden until the full catalog is shown.
    expect(within(table).queryByText('Checkov')).not.toBeInTheDocument()
    expect(within(table).getByText('1/2 online')).toBeInTheDocument()
    expect(within(table).getByText('v3.3.0 – v3.4.2')).toBeInTheDocument()
    expect(within(table).getByText('Offline only')).toBeInTheDocument()
    // The install method is not a column any more.
    expect(within(table).queryByText('Install')).not.toBeInTheDocument()
  })

  it('shows the full catalog behind the switch', async () => {
    render(<ToolsSection />)
    await userEvent.click(screen.getByLabelText('Show full catalog'))
    expect(within(screen.getByRole('table')).getByText('Checkov')).toBeInTheDocument()
  })

  it('the No sensor metric filters to those tools across the catalog', async () => {
    render(<ToolsSection />)
    await userEvent.click(screen.getByRole('button', { name: /no sensor/i }))
    const table = screen.getByRole('table')
    expect(within(table).getByText('Checkov')).toBeInTheDocument()
    expect(within(table).queryByText('Nuclei')).not.toBeInTheDocument()
  })

  it('the switch turns a tool off for the organization', async () => {
    render(<ToolsSection />)
    await userEvent.click(screen.getByRole('switch', { name: 'Disable Nuclei' }))
    expect(disable).toHaveBeenCalledWith('id-nuclei')
  })

  it('says so when no sensor reported a tool yet', () => {
    availability = { ...availability!, items: [checkov] }
    render(<ToolsSection />)
    expect(screen.getByText('No sensor has reported a tool yet')).toBeInTheDocument()
  })
})
