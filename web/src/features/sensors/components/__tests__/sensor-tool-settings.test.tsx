import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'

import en from '@/lib/i18n/dictionaries/en/sensors.json'
import vi_ from '@/lib/i18n/dictionaries/vi/sensors.json'
import { ApiClientError } from '@/lib/api/error-handler'
import type { SensorToolSettings } from '@/lib/api/sensor-tool-settings-hooks'

const perms = { write: true }
const api = vi.hoisted(() => ({
  items: [] as unknown[],
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
    useSensorToolSettings: () => ({
      data: { items: api.items },
      error: undefined,
      isLoading: false,
      mutate: api.mutate,
    }),
    useSensorEffectiveToolSettings: () => ({
      data: {
        tool: 'nuclei',
        schema_digest: 'sha256:1',
        items: [
          { key: 'rate_limit', value: 300, source: 'sensor', flag: '-rate-limit', scope: 'scan' },
        ],
      },
      error: undefined,
      isLoading: false,
    }),
    saveSensorToolSettings: api.save,
    resetSensorToolSettings: api.reset,
  }
})

import { SensorToolSettingsSection } from '../sensor-tool-settings'

const item: SensorToolSettings = {
  tool: 'nuclei',
  schema_digest: 'sha256:1',
  schema: {
    type: 'object',
    properties: {
      scan_strategy: { type: 'string', enum: ['auto', 'host-spray'], default: 'auto' },
      rate_limit: {
        type: 'integer',
        minimum: 1,
        maximum: 5000,
        default: 150,
        'x-octm-common': 'rate',
        'x-octm-flag': '-rate-limit',
      },
      headless: { type: 'boolean', default: false, 'x-octm-tier': 'T2' },
    },
  },
  values: { rate_limit: 300 },
  stored: true,
  problems: [],
}

describe('SensorToolSettingsSection', () => {
  beforeEach(() => {
    perms.write = true
    api.items = [item]
    api.save.mockReset()
    api.reset.mockReset()
    api.mutate.mockReset()
  })

  it('renders nothing without sensors:write', () => {
    perms.write = false
    const { container } = render(<SensorToolSettingsSection sensorId="s1" />)
    expect(container).toBeEmptyDOMElement()
  })

  it('renders the common options first, bounded, with defaults as placeholders', () => {
    render(<SensorToolSettingsSection sensorId="s1" />)
    const form = screen.getByTestId('tool-settings-nuclei')
    const rows = within(form).getAllByTestId(/^tool-setting-/)
    expect(rows[0]).toHaveAttribute('data-testid', 'tool-setting-rate_limit')
    const rate = within(form).getByLabelText(en['sensors.toolOptions.common.rate'])
    expect(rate).toHaveAttribute('min', '1')
    expect(rate).toHaveAttribute('max', '5000')
    expect(rate).toHaveAttribute('placeholder', '150')
    expect(rate).toHaveValue(300)
    // A dangerous option is locked at its default.
    expect(within(form).getByLabelText('headless')).toBeDisabled()
  })

  it('saves the draft and shows server problems by path', async () => {
    api.save.mockRejectedValueOnce(
      new ApiClientError('invalid', 'VALIDATION_FAILED', 422, [
        { path: '/rate_limit', message: 'above the maximum' },
      ] as unknown as Record<string, unknown>)
    )
    render(<SensorToolSettingsSection sensorId="s1" />)
    const rate = screen.getByLabelText(en['sensors.toolOptions.common.rate'])
    fireEvent.change(rate, { target: { value: '9000' } })
    fireEvent.click(screen.getByRole('button', { name: en['sensors.toolSettings.save'] }))
    await waitFor(() => expect(api.save).toHaveBeenCalledWith('s1', 'nuclei', { rate_limit: 9000 }))
    expect(await screen.findByText('above the maximum')).toBeInTheDocument()

    api.save.mockResolvedValueOnce(item)
    fireEvent.change(rate, { target: { value: '200' } })
    fireEvent.click(screen.getByRole('button', { name: en['sensors.toolSettings.save'] }))
    await waitFor(() => expect(api.mutate).toHaveBeenCalled())
  })

  it('resets to defaults', async () => {
    api.reset.mockResolvedValueOnce(undefined)
    render(<SensorToolSettingsSection sensorId="s1" />)
    fireEvent.click(screen.getByRole('button', { name: en['sensors.toolSettings.reset'] }))
    await waitFor(() => expect(api.reset).toHaveBeenCalledWith('s1', 'nuclei'))
    expect(api.mutate).toHaveBeenCalled()
  })

  it('shows the effective values with their source and native flag', () => {
    render(<SensorToolSettingsSection sensorId="s1" />)
    fireEvent.click(screen.getByRole('button', { name: en['sensors.toolSettings.showEffective'] }))
    const table = screen.getByTestId('tool-settings-effective-nuclei')
    expect(within(table).getByText('-rate-limit')).toBeInTheDocument()
    expect(within(table).getByText(en['sensors.toolSettings.source.sensor'])).toBeInTheDocument()
  })

  it('has every tool settings key in English and Vietnamese', () => {
    const enKeys = Object.keys(en).filter((k) => k.startsWith('sensors.toolSettings.'))
    const viKeys = Object.keys(vi_).filter((k) => k.startsWith('sensors.toolSettings.'))
    expect(enKeys.length).toBeGreaterThan(20)
    expect(viKeys.sort()).toEqual(enKeys.sort())
  })
})
