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
vi.mock('@/lib/api/sensor-hooks', () => ({
  useSensorManifests: () => ({
    data: {
      items: [
        {
          current: true,
          manifest: { tools: [{ name: 'nuclei', version: 'v3.4.2', installed: true }] },
        },
      ],
    },
  }),
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
          {
            key: 'rate_limit',
            value: 300,
            source: 'sensor',
            flag: '-rate-limit',
            scope: 'scan',
            chain: [
              { source: 'default', value: 150 },
              { source: 'tenant', value: 200 },
              { source: 'sensor', value: 300 },
            ],
          },
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
      scan_strategy: {
        type: 'string',
        enum: ['auto', 'host-spray'],
        default: 'auto',
        'x-octm-group': 'Performance',
      },
      rate_limit: {
        type: 'integer',
        minimum: 1,
        maximum: 5000,
        default: 150,
        'x-octm-common': 'rate',
        'x-octm-flag': '-rate-limit',
      },
      timeout: {
        type: 'integer',
        default: 10,
        'x-octm-common': 'timeout',
        'x-octm-flag': '-timeout',
      },
      retries: {
        type: 'integer',
        default: 1,
        'x-octm-common': 'retries',
        'x-octm-flag': '-retries',
      },
      concurrency: {
        type: 'integer',
        default: 25,
        'x-octm-common': 'concurrency',
        'x-octm-flag': '-c',
      },
      headless: {
        type: 'boolean',
        default: false,
        'x-octm-tier': 'T2',
        'x-octm-group': 'Advanced',
      },
      follow_redirects: {
        type: 'boolean',
        default: false,
        'x-octm-tier': 'T1',
        'x-octm-group': 'Advanced',
      },
    },
  },
  values: { rate_limit: 300 },
  stored: true,
  problems: [],
}

const plain = (tool: string): SensorToolSettings => ({
  tool,
  schema_digest: `sha256:${tool}`,
  schema: {
    type: 'object',
    properties: {
      depth: { type: 'integer', default: 3, 'x-octm-flag': '-depth', 'x-octm-group': 'Crawl' },
    },
  },
  values: {},
  stored: false,
  problems: [],
})

const toolNames = () =>
  screen
    .getAllByTestId(/^tool-settings-(?!summary|savebar|group|effective)[a-z]+$/)
    .map((n) => n.getAttribute('data-tool'))

const openTool = (tool: string) =>
  fireEvent.click(within(screen.getByTestId(`tool-settings-${tool}`)).getAllByRole('button')[0])

const saveName = (tool: string) => en['sensors.toolSettings.saveTool'].replace('{tool}', tool)

describe('SensorToolSettingsSection', () => {
  beforeEach(() => {
    perms.write = true
    api.items = [item]
    api.save.mockReset()
    api.reset.mockReset()
    api.mutate.mockReset()
    window.localStorage.clear()
  })

  it('renders nothing without sensors:write', () => {
    perms.write = false
    const { container } = render(<SensorToolSettingsSection sensorId="s1" />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows each tool collapsed with its version and a summary', () => {
    api.items = [plain('katana'), item]
    render(<SensorToolSettingsSection sensorId="s1" />)
    expect(screen.queryByTestId('tool-setting-rate_limit')).not.toBeInTheDocument()
    expect(screen.getByText('v3.4.2')).toBeInTheDocument()
    expect(screen.getByTestId('tool-settings-summary-katana')).toHaveTextContent(
      en['sensors.toolSettings.allDefaults']
    )
    expect(screen.getByTestId('tool-settings-summary-nuclei')).toHaveTextContent(
      '1 overridden: rate-limit 300'
    )
  })

  it('caps the changed options listed in the summary', () => {
    api.items = [{ ...item, values: { rate_limit: 300, timeout: 20, retries: 3, concurrency: 50 } }]
    render(<SensorToolSettingsSection sensorId="s1" />)
    expect(screen.getByTestId('tool-settings-summary-nuclei')).toHaveTextContent(
      '4 overridden: timeout 20, rate-limit 300, c 50, …'
    )
  })

  it('lists tools with changes first, then by name', () => {
    api.items = [plain('subfinder'), plain('httpx'), item, plain('katana')]
    render(<SensorToolSettingsSection sensorId="s1" />)
    expect(toolNames()).toEqual(['nuclei', 'httpx', 'katana', 'subfinder'])
  })

  it('opens the common options; other groups are collapsed with their changed count', () => {
    api.items = [{ ...item, values: { rate_limit: 300, scan_strategy: 'host-spray' } }]
    render(<SensorToolSettingsSection sensorId="s1" />)
    openTool('nuclei')
    expect(screen.getByTestId('tool-setting-rate_limit')).toBeInTheDocument()
    expect(screen.queryByTestId('tool-setting-scan_strategy')).not.toBeInTheDocument()
    expect(screen.getByTestId('tool-settings-group-group:Performance')).toHaveTextContent(
      en['sensors.toolSettings.groupOverridden'].replace('{count}', '1')
    )
  })

  it('renders the common options first, bounded, with defaults as placeholders', () => {
    render(<SensorToolSettingsSection sensorId="s1" />)
    openTool('nuclei')
    const form = screen.getByTestId('tool-settings-nuclei')
    const rows = within(form).getAllByTestId(/^tool-setting-(?!changed)/)
    expect(rows[0]).toHaveAttribute('data-testid', 'tool-setting-timeout')
    const rate = within(form).getByLabelText(en['sensors.toolOptions.common.rate'])
    expect(rate).toHaveAttribute('min', '1')
    expect(rate).toHaveAttribute('max', '5000')
    expect(rate).toHaveAttribute('placeholder', '150')
    expect(rate).toHaveValue(300)
    // Impact options keep their badge and a warning; a dangerous one is locked.
    fireEvent.click(
      within(screen.getByTestId('tool-settings-group-group:Advanced')).getByRole('button')
    )
    expect(within(form).getByLabelText('headless')).toBeDisabled()
    expect(
      within(form).getByText(en['sensors.toolSettings.impactWarning'], { exact: false })
    ).toHaveTextContent(en['sensors.toolSettings.impactStepUp'])
    expect(within(form).getByText(en['sensors.toolSettings.t2Locked'])).toBeInTheDocument()
  })

  it('remembers the open tools per sensor and works without storage', () => {
    const { unmount } = render(<SensorToolSettingsSection sensorId="s1" />)
    openTool('nuclei')
    unmount()
    render(<SensorToolSettingsSection sensorId="s1" />)
    expect(screen.getByTestId('tool-setting-rate_limit')).toBeInTheDocument()

    const get = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked')
    })
    const set = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked')
    })
    try {
      const other = render(<SensorToolSettingsSection sensorId="s2" />)
      expect(
        within(other.container).queryByTestId('tool-setting-rate_limit')
      ).not.toBeInTheDocument()
    } finally {
      get.mockRestore()
      set.mockRestore()
    }
  })

  it('on a phone, opening a tool scrolls the drawer body only, never the frame around it', async () => {
    const mm = window.matchMedia
    window.matchMedia = ((q: string) => ({
      matches: q.includes('max-width'),
      media: q,
      addEventListener: () => {},
      removeEventListener: () => {},
    })) as unknown as typeof window.matchMedia
    const intoView = vi.fn()
    const orig = Element.prototype.scrollIntoView
    Element.prototype.scrollIntoView = intoView
    try {
      api.items = [plain('katana'), item]
      // frame (overflow hidden, like the drawer) > body (scrolls) > section
      const frame = document.createElement('div')
      frame.style.overflowY = 'hidden'
      const body = document.createElement('div')
      body.style.overflowY = 'auto'
      frame.appendChild(body)
      document.body.appendChild(frame)
      render(<SensorToolSettingsSection sensorId="s1" />, { container: body })
      body.getBoundingClientRect = () => ({ top: 200, height: 500 }) as DOMRect
      const katana = screen.getByTestId('tool-settings-katana')
      katana.getBoundingClientRect = () => ({ top: 650, height: 600 }) as DOMRect
      fireEvent.click(within(katana).getAllByRole('button')[0])
      await waitFor(() => expect(body.scrollTop).toBe(450))
      expect(frame.scrollTop).toBe(0)
      expect(intoView).not.toHaveBeenCalled()
      frame.remove()
    } finally {
      window.matchMedia = mm
      Element.prototype.scrollIntoView = orig
    }
  })

  it('search filters by tool or option name and opens the matching tool', () => {
    api.items = [plain('katana'), item]
    render(<SensorToolSettingsSection sensorId="s1" />)
    const search = screen.getByLabelText(en['sensors.toolSettings.searchLabel'])
    fireEvent.change(search, { target: { value: 'strategy' } })
    expect(screen.getByTestId('tool-settings-katana')).not.toBeVisible()
    // The tool and the group holding the option are open, the option marked.
    expect(screen.getByTestId('tool-setting-scan_strategy')).toHaveAttribute(
      'data-search-match',
      'true'
    )
    fireEvent.change(search, { target: { value: 'katana' } })
    expect(screen.getByTestId('tool-settings-katana')).toBeVisible()
    expect(screen.getByTestId('tool-setting-depth')).toBeInTheDocument()
    fireEvent.change(search, { target: { value: 'zzz' } })
    expect(
      screen.getByText(en['sensors.toolSettings.searchEmpty'].replace('{query}', 'zzz'))
    ).toBeInTheDocument()
  })

  it('shows the save bar only with unsaved changes; resets one option', () => {
    render(<SensorToolSettingsSection sensorId="s1" />)
    openTool('nuclei')
    expect(screen.queryByTestId('tool-settings-savebar-nuclei')).not.toBeInTheDocument()
    expect(screen.getByTestId('tool-setting-changed-rate_limit')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText(en['sensors.toolOptions.common.timeout']), {
      target: { value: '20' },
    })
    expect(screen.getByTestId('tool-settings-savebar-nuclei')).toBeInTheDocument()
    fireEvent.click(
      screen.getByRole('button', {
        name: en['sensors.toolSettings.resetToToolLabel'].replace(
          '{option}',
          en['sensors.toolOptions.common.timeout']
        ),
      })
    )
    expect(screen.queryByTestId('tool-settings-savebar-nuclei')).not.toBeInTheDocument()
    fireEvent.click(
      screen.getByRole('button', {
        name: en['sensors.toolSettings.resetToToolLabel'].replace(
          '{option}',
          en['sensors.toolOptions.common.rate']
        ),
      })
    )
    expect(screen.getByLabelText(en['sensors.toolOptions.common.rate'])).toHaveValue(null)
    expect(screen.getByTestId('tool-settings-savebar-nuclei')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: en['sensors.toolSettings.discard'] }))
    expect(screen.getByLabelText(en['sensors.toolOptions.common.rate'])).toHaveValue(300)
  })

  it('saves the draft and shows server problems by path', async () => {
    api.save.mockRejectedValueOnce(
      new ApiClientError('invalid', 'VALIDATION_FAILED', 422, [
        { path: '/rate_limit', message: 'above the maximum' },
      ] as unknown as Record<string, unknown>)
    )
    render(<SensorToolSettingsSection sensorId="s1" />)
    openTool('nuclei')
    const rate = screen.getByLabelText(en['sensors.toolOptions.common.rate'])
    fireEvent.change(rate, { target: { value: '9000' } })
    fireEvent.click(screen.getByRole('button', { name: saveName('nuclei') }))
    await waitFor(() => expect(api.save).toHaveBeenCalledWith('s1', 'nuclei', { rate_limit: 9000 }))
    expect(await screen.findByText('above the maximum')).toBeInTheDocument()

    api.save.mockResolvedValueOnce(item)
    fireEvent.change(rate, { target: { value: '200' } })
    fireEvent.click(screen.getByRole('button', { name: saveName('nuclei') }))
    await waitFor(() => expect(api.mutate).toHaveBeenCalled())
  })

  it('reset tool clears every option; saving it drops the stored settings', async () => {
    api.reset.mockResolvedValueOnce(undefined)
    render(<SensorToolSettingsSection sensorId="s1" />)
    openTool('nuclei')
    fireEvent.click(
      screen.getByRole('button', { name: en['sensors.toolSettings.resetAllOverrides'] })
    )
    expect(screen.getByTestId('tool-settings-summary-nuclei')).toHaveTextContent(
      en['sensors.toolSettings.allDefaults']
    )
    expect(api.reset).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: saveName('nuclei') }))
    await waitFor(() => expect(api.reset).toHaveBeenCalledWith('s1', 'nuclei'))
    expect(api.save).not.toHaveBeenCalled()
    expect(api.mutate).toHaveBeenCalled()
  })

  it('inherits the organization defaults: source, placeholder, override and reset', () => {
    api.items = [
      {
        ...item,
        values: { rate_limit: 300 },
        organization_values: { rate_limit: 150, timeout: 20 },
      },
    ]
    render(<SensorToolSettingsSection sensorId="s1" />)
    expect(screen.getByTestId('tool-settings-summary-nuclei')).toHaveTextContent(
      '1 overridden: rate-limit 300'
    )
    openTool('nuclei')
    const timeout = screen.getByLabelText(en['sensors.toolOptions.common.timeout'])
    // Inherited: empty input, the organization's value as placeholder.
    expect(timeout).toHaveValue(null)
    expect(timeout).toHaveAttribute('placeholder', '20')
    expect(screen.getByTestId('tool-setting-source-timeout')).toHaveAttribute(
      'data-source',
      'tenant'
    )
    expect(screen.getByTestId('tool-setting-source-timeout')).toHaveTextContent(
      `20 · ${en['sensors.toolSettings.source.tenant']}`
    )
    // Overridden here: the sensor is the source; reset goes back to the organization's.
    expect(screen.getByTestId('tool-setting-source-rate_limit')).toHaveAttribute(
      'data-source',
      'sensor'
    )
    expect(screen.getByTestId('tool-setting-source-rate_limit')).toHaveTextContent(
      `300 · ${en['sensors.toolSettings.source.sensor']}`
    )
    fireEvent.click(
      screen.getByRole('button', {
        name: en['sensors.toolSettings.resetToOrgLabel'].replace(
          '{option}',
          en['sensors.toolOptions.common.rate']
        ),
      })
    )
    expect(screen.getByTestId('tool-setting-source-rate_limit')).toHaveAttribute(
      'data-source',
      'tenant'
    )
    // Not set anywhere: the tool default.
    expect(screen.getByTestId('tool-setting-source-retries')).toHaveAttribute(
      'data-source',
      'default'
    )
    // Override copies the inherited value into the field.
    fireEvent.click(
      screen.getByRole('button', {
        name: en['sensors.toolSettings.overrideLabel'].replace(
          '{option}',
          en['sensors.toolOptions.common.timeout']
        ),
      })
    )
    expect(timeout).toHaveValue(20)
    expect(screen.getByTestId('tool-setting-source-timeout')).toHaveAttribute(
      'data-source',
      'sensor'
    )
  })

  it('a sensor without overrides shows how many organization defaults it inherits', () => {
    api.items = [{ ...item, values: {}, stored: false, organization_values: { rate_limit: 150 } }]
    render(<SensorToolSettingsSection sensorId="s1" />)
    expect(screen.getByTestId('tool-settings-summary-nuclei')).toHaveTextContent(
      en['sensors.toolSettings.inheritsOrg'].replace('{count}', '1')
    )
  })

  it('warns when the organization defaults do not fit this sensor', () => {
    api.items = [
      {
        ...item,
        organization_values: { rate_limit: 9000 },
        organization_problems: [{ path: '/rate_limit', message: 'above the maximum' }],
      },
    ]
    render(<SensorToolSettingsSection sensorId="s1" />)
    openTool('nuclei')
    const notice = screen.getByTestId('tool-settings-notice-nuclei')
    expect(notice).toHaveTextContent(en['sensors.toolSettings.orgProblems'])
    expect(notice).toHaveTextContent('rate_limit: above the maximum')
  })

  it('links to the organization tool defaults', () => {
    render(<SensorToolSettingsSection sensorId="s1" />)
    expect(
      screen.getByRole('link', { name: en['sensors.toolSettings.manageDefaults'] })
    ).toHaveAttribute('href', '/settings/scanning/tool-defaults')
  })

  it('shows the effective values with their source and native flag', () => {
    render(<SensorToolSettingsSection sensorId="s1" />)
    openTool('nuclei')
    fireEvent.click(screen.getByRole('button', { name: en['sensors.toolSettings.showEffective'] }))
    const table = screen.getByTestId('tool-settings-effective-nuclei')
    expect(within(table).getByText('-rate-limit')).toBeInTheDocument()
    expect(within(table).getByText(en['sensors.toolSettings.source.sensor'])).toBeInTheDocument()
    // The layers it overrides, lowest first.
    expect(screen.getByTestId('tool-settings-chain-rate_limit')).toHaveTextContent(
      `over 150 (${en['sensors.toolSettings.source.default']}), 200 (${en['sensors.toolSettings.source.tenant']})`
    )
  })

  it('has every tool settings key in English and Vietnamese', () => {
    const enKeys = Object.keys(en).filter((k) => k.startsWith('sensors.toolSettings.'))
    const viKeys = Object.keys(vi_).filter((k) => k.startsWith('sensors.toolSettings.'))
    expect(enKeys.length).toBeGreaterThan(20)
    expect(viKeys.sort()).toEqual(enKeys.sort())
  })
})
