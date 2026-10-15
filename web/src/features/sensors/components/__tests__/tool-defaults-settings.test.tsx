import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'

import en from '@/lib/i18n/dictionaries/en/sensors.json'
import vi_ from '@/lib/i18n/dictionaries/vi/sensors.json'
import type { ToolDefaults } from '@/lib/api/sensor-tool-settings-hooks'

const perms = { write: true }
const api = vi.hoisted(() => ({
  items: [] as unknown[],
  error: undefined as unknown,
  save: vi.fn(),
  reset: vi.fn(),
  mutate: vi.fn(),
}))

vi.mock('@/lib/permissions', () => ({
  Permission: { SensorsWrite: 'sensors:write' },
  useHasPermission: () => perms.write,
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/lib/api/sensor-tool-settings-hooks', async (orig) => {
  const actual = await orig<typeof import('@/lib/api/sensor-tool-settings-hooks')>()
  return {
    ...actual,
    useToolDefaults: () => ({
      data: api.error ? undefined : { items: api.items },
      error: api.error,
      isLoading: false,
      mutate: api.mutate,
    }),
    saveToolDefaults: api.save,
    resetToolDefaults: api.reset,
  }
})

import { ToolDefaultsSettings } from '../tool-defaults-settings'

const nuclei: ToolDefaults = {
  tool: 'nuclei',
  schema_digest: 'sha256:1',
  schema: {
    type: 'object',
    properties: {
      rate_limit: {
        type: 'integer',
        minimum: 1,
        maximum: 5000,
        default: 150,
        'x-octm-common': 'rate',
        'x-octm-flag': '-rate-limit',
      },
      follow_redirects: {
        type: 'boolean',
        default: false,
        'x-octm-tier': 'T1',
        'x-octm-group': 'Advanced',
      },
    },
  },
  values: { rate_limit: 900 },
  stored: true,
  sensors: 3,
  problems: [],
}

const openTool = (tool: string) =>
  fireEvent.click(within(screen.getByTestId(`tool-settings-${tool}`)).getAllByRole('button')[0])

describe('ToolDefaultsSettings', () => {
  beforeEach(() => {
    perms.write = true
    api.items = [nuclei]
    api.error = undefined
    api.save.mockReset()
    api.reset.mockReset()
    api.mutate.mockReset()
    window.localStorage.clear()
  })

  it('lists each tool with its sensor count and changed options, options from the schema', () => {
    render(<ToolDefaultsSettings />)
    expect(screen.getByText(en['sensors.toolDefaults.title'])).toBeInTheDocument()
    expect(screen.getByTestId('tool-settings-nuclei')).toHaveTextContent(
      en['sensors.toolDefaults.sensorsCount.other'].replace('{count}', '3')
    )
    expect(screen.getByTestId('tool-settings-summary-nuclei')).toHaveTextContent(
      '1 changed: rate-limit 900'
    )
    openTool('nuclei')
    const rate = screen.getByLabelText(en['sensors.toolOptions.common.rate'])
    expect(rate).toHaveValue(900)
    expect(rate).toHaveAttribute('placeholder', '150')
    // Organization mode: no per-option source line, no Override button.
    expect(screen.queryByTestId('tool-setting-source-rate_limit')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /override/i })).not.toBeInTheDocument()
  })

  it('saves the organization defaults; back to every default resets them', async () => {
    api.save.mockResolvedValue(nuclei)
    api.reset.mockResolvedValue(undefined)
    render(<ToolDefaultsSettings />)
    openTool('nuclei')
    fireEvent.change(screen.getByLabelText(en['sensors.toolOptions.common.rate']), {
      target: { value: '400' },
    })
    const saveName = en['sensors.toolSettings.saveTool'].replace('{tool}', 'nuclei')
    fireEvent.click(screen.getByRole('button', { name: saveName }))
    await waitFor(() => expect(api.save).toHaveBeenCalledWith('nuclei', { rate_limit: 400 }))
    await waitFor(() => expect(api.mutate).toHaveBeenCalled())

    fireEvent.click(screen.getByRole('button', { name: en['sensors.toolSettings.resetTool'] }))
    fireEvent.click(screen.getByRole('button', { name: saveName }))
    await waitFor(() => expect(api.reset).toHaveBeenCalledWith('nuclei'))
  })

  it('names the sensors whose tool version refuses the defaults', () => {
    api.items = [
      {
        ...nuclei,
        problems: [
          {
            sensor_id: 's2',
            sensor_name: 'dmz-sensor-02',
            problems: [{ path: '/rate_limit', message: 'above the maximum 500' }],
          },
        ],
      },
    ]
    render(<ToolDefaultsSettings />)
    openTool('nuclei')
    expect(screen.getByTestId('tool-settings-notice-nuclei')).toHaveTextContent(
      'dmz-sensor-02: rate_limit: above the maximum 500'
    )
  })

  it('is read-only without sensors:write', () => {
    perms.write = false
    render(<ToolDefaultsSettings />)
    expect(screen.getByText(en['sensors.toolDefaults.readOnly'])).toBeInTheDocument()
    openTool('nuclei')
    expect(screen.getByLabelText(en['sensors.toolOptions.common.rate'])).toBeDisabled()
    expect(screen.queryByTestId('tool-settings-savebar-nuclei')).not.toBeInTheDocument()
  })

  it('shows the empty state when no sensor reports a tool with settings', () => {
    api.items = []
    render(<ToolDefaultsSettings />)
    expect(screen.getByText(en['sensors.toolDefaults.emptyTitle'])).toBeInTheDocument()
  })

  it('has every tool defaults key in English and Vietnamese', () => {
    const keys = (d: Record<string, string>) =>
      Object.keys(d).filter((k) => k.startsWith('sensors.toolDefaults.'))
    expect(keys(vi_ as Record<string, string>).sort()).toEqual(
      keys(en as Record<string, string>).sort()
    )
    expect(keys(en as Record<string, string>).length).toBeGreaterThan(5)
  })
})
