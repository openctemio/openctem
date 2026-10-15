import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { availableFormats, SensorInstallSnippets } from '../sensor-install-snippets'
import { TEST_SENSOR_KEY } from '@/test/sensor-keys'

// Radix Select scrolls the chosen option into view; jsdom has no layout.
Element.prototype.scrollIntoView = vi.fn()

// The product catalog comes from GET /sensors/stats.
const stats: {
  data?: { products: { id: string; latest_version: string; min_version: string; image: string }[] }
} = {}
vi.mock('@/lib/api/sensor-hooks', () => ({ useTenantSensorStats: () => stats }))

const templates = {
  docker: `docker run -d --name dmz \\\n  -e SENSOR_API_KEY='${TEST_SENSOR_KEY}' \\\n  ghcr.io/openctemio/sensor:v0.4.2\n`,
  compose: 'services:\n  sensor:\n    image: ghcr.io/openctemio/sensor:v0.4.2\n',
  kubernetes: 'apiVersion: v1\nkind: Secret\n',
  helm: 'helm upgrade openctem openctem/openctem --reuse-values \\\n  --set sensor.enabled=true\n',
  policy: 'apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  allow:\n    - "10.20.0.0/16"\n',
  yaml: 'sensor:\n  name: dmz\n',
  env: "export SENSOR_API_URL='https://x'\n",
  cli: './openctemio-sensor -daemon\n',
  image: 'ghcr.io/openctemio/sensor:v0.4.2',
  product: 'openctemio-sensor',
  api_url: 'https://192.0.2.204',
  api_key_included: true,
  ca_certificate: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n',
  ca_fingerprint_sha256: 'AA:BB',
}

function mockFetch(body: unknown, ok = true) {
  const fn = vi.fn(async () => ({ ok, status: ok ? 200 : 500, json: async () => body }))
  vi.stubGlobal('fetch', fn)
  return fn
}

afterEach(() => {
  vi.unstubAllGlobals()
  stats.data = undefined
})

describe('availableFormats', () => {
  it('lists the formats the API rendered, in order (older APIs send four)', () => {
    expect(availableFormats(templates)).toEqual([
      'docker',
      'compose',
      'kubernetes',
      'helm',
      'policy',
      'yaml',
      'env',
      'cli',
    ])
    expect(availableFormats({ docker: 'x', yaml: 'y', env: '', cli: 'c' })).toEqual([
      'docker',
      'yaml',
      'cli',
    ])
  })
})

describe('SensorInstallSnippets', () => {
  it('offers the sensor-local policy as a downloadable file for the network owner', async () => {
    mockFetch(templates)
    const user = userEvent.setup()
    render(<SensorInstallSnippets sensorId="11111111-1111-4111-8111-111111111111" />)
    await user.click(await screen.findByRole('tab', { name: 'Local policy' }))
    expect(
      await screen.findByText((text) => text.includes('apiVersion: openctem.io/sensor-policy/v1'))
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Download sensor-policy.yaml' })).toBeInTheDocument()
    expect(screen.getByText(/the platform cannot change it/)).toBeInTheDocument()
  })

  it('sends a just-issued key in a header (never the URL) and renders the commands', async () => {
    const fetchFn = mockFetch(templates)
    render(
      <SensorInstallSnippets
        sensorId="11111111-1111-4111-8111-111111111111"
        apiKey={TEST_SENSOR_KEY}
      />
    )
    await screen.findByText(/docker run -d --name dmz/)
    const [url, init] = fetchFn.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe('/api/v1/sensors/11111111-1111-4111-8111-111111111111/config-templates')
    expect(url).not.toContain(TEST_SENSOR_KEY)
    expect((init.headers as Record<string, string>)['X-Sensor-API-Key']).toBe(TEST_SENSOR_KEY)
    expect(init.cache).toBe('no-store')
    expect(
      screen.getByText('ghcr.io/openctemio/sensor:v0.4.2', { selector: 'span' })
    ).toBeInTheDocument()
    for (const tab of [
      'docker run',
      'Compose',
      'Kubernetes',
      'Helm',
      'Config file',
      'Env',
      'Binary',
    ]) {
      expect(screen.getByRole('tab', { name: tab })).toBeInTheDocument()
    }
  })

  it('switches format and explains the private CA with its fingerprint', async () => {
    mockFetch(templates)
    render(<SensorInstallSnippets sensorId="s1" />)
    await screen.findByRole('tab', { name: 'Compose' })
    await userEvent.click(screen.getByRole('tab', { name: 'Compose' }))
    await waitFor(() => expect(screen.getByText(/services:/)).toBeInTheDocument())
    expect(screen.getByText(/private certificate authority/)).toBeInTheDocument()
    expect(screen.getByText('AA:BB')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Download CA certificate/ })).toBeInTheDocument()
  })

  it('no CA note when the platform certificate is public; an error state on failure', async () => {
    mockFetch({ ...templates, ca_certificate: '', ca_fingerprint_sha256: '' })
    const { unmount } = render(<SensorInstallSnippets sensorId="s1" />)
    await screen.findByRole('tab', { name: 'docker run' })
    expect(screen.queryByText(/private certificate authority/)).toBeNull()
    unmount()
    mockFetch({}, false)
    render(<SensorInstallSnippets sensorId="s2" />)
    expect(await screen.findByRole('alert')).toBeInTheDocument()
  })

  it('picks a catalog product: its snippets come from ?product=, and a custom one links the guide', async () => {
    stats.data = {
      products: [
        { id: 'openctemio-sensor', latest_version: 'v0.4.2', min_version: '', image: 'i' },
        {
          id: 'openctemio-connector-tenable',
          latest_version: 'v0.1.0',
          min_version: '',
          image: 'c',
        },
      ],
    }
    const connector = {
      docker: 'docker run -d --name dmz ghcr.io/openctemio/connector-tenable:v0.1.0\n',
      compose: 'services:\n  connector:\n',
      yaml: '',
      env: '',
      cli: '',
      image: 'ghcr.io/openctemio/connector-tenable:v0.1.0',
      product: 'openctemio-connector-tenable',
    }
    const fetchFn = vi.fn(async (url: string) => ({
      ok: true,
      status: 200,
      json: async () =>
        url.includes('product=openctemio-connector-tenable') ? connector : templates,
    }))
    vi.stubGlobal('fetch', fetchFn)
    const user = userEvent.setup()
    render(<SensorInstallSnippets sensorId="11111111-1111-4111-8111-111111111111" />)
    // The API chose the default: the scanning sensor.
    await screen.findByText(/ghcr.io\/openctemio\/sensor:v0.4.2/, { selector: 'pre' })
    expect((fetchFn.mock.calls[0] as unknown as [string])[0]).not.toContain('product=')

    await user.click(screen.getByRole('combobox', { name: 'Product' }))
    await user.click(await screen.findByRole('option', { name: 'Tenable.sc connector' }))
    await screen.findByText(/connector-tenable:v0.1.0/, { selector: 'pre' })
    const last = fetchFn.mock.calls.at(-1) as unknown as [string]
    expect(last[0]).toBe(
      '/api/v1/sensors/11111111-1111-4111-8111-111111111111/config-templates?product=openctemio-connector-tenable'
    )
    // Only the formats the connector ships.
    expect(screen.queryByRole('tab', { name: 'Kubernetes' })).toBeNull()

    await user.click(screen.getByRole('combobox', { name: 'Product' }))
    await user.click(
      await screen.findByRole('option', { name: 'Custom sensor (built on the SDK)' })
    )
    const guide = await screen.findByRole('link', { name: /Tool-author guide/ })
    expect(guide).toHaveAttribute('href', 'https://docs.openctem.io/developers/tool-authoring/')
    expect(guide).toHaveAttribute('rel', 'noopener noreferrer')
    expect(screen.queryByRole('tab')).toBeNull()
  })

  it('lists a product the console has never heard of by its id and renders its snippets', async () => {
    // A customer's own sensor product, added as data on the API
    // (SENSOR_PRODUCTS_FILE + its template set): no console code names it.
    stats.data = {
      products: [
        { id: 'openctemio-sensor', latest_version: 'v0.4.2', min_version: '', image: 'i' },
        {
          id: 'acme-toy-sensor',
          latest_version: 'v1.2.3',
          min_version: 'v1.0.0',
          image: 'ghcr.io/acme/toy-sensor:v1.2.3',
        },
      ],
    }
    const toy = {
      docker: 'docker run -d --name acme-toy-sensor ghcr.io/acme/toy-sensor:v1.2.3\n',
      env: 'TOY_PLATFORM_URL=https://192.0.2.204\n',
      yaml: '',
      cli: '',
      compose: '',
      image: 'ghcr.io/acme/toy-sensor:v1.2.3',
      product: 'acme-toy-sensor',
    }
    const fetchFn = vi.fn(async (url: string) => ({
      ok: true,
      status: 200,
      json: async () => (url.includes('product=acme-toy-sensor') ? toy : templates),
    }))
    vi.stubGlobal('fetch', fetchFn)
    const user = userEvent.setup()
    render(<SensorInstallSnippets sensorId="11111111-1111-4111-8111-111111111111" />)
    await screen.findByText(/ghcr.io\/openctemio\/sensor:v0.4.2/, { selector: 'pre' })

    await user.click(screen.getByRole('combobox', { name: 'Product' }))
    await user.click(await screen.findByRole('option', { name: 'acme-toy-sensor' }))
    await screen.findByText(/ghcr.io\/acme\/toy-sensor:v1.2.3/, { selector: 'pre' })
    const last = fetchFn.mock.calls.at(-1) as unknown as [string]
    expect(last[0]).toBe(
      '/api/v1/sensors/11111111-1111-4111-8111-111111111111/config-templates?product=acme-toy-sensor'
    )
    expect(screen.queryByRole('tab', { name: 'Kubernetes' })).toBeNull()
  })

  it('shows no product picker for a collector (its snippets name no product)', async () => {
    stats.data = {
      products: [
        { id: 'openctemio-sensor', latest_version: 'v0.4.2', min_version: '', image: 'i' },
      ],
    }
    mockFetch({ ...templates, product: '' })
    render(<SensorInstallSnippets sensorId="11111111-1111-4111-8111-111111111111" />)
    await screen.findByText(/docker run -d --name dmz/)
    expect(screen.queryByRole('combobox', { name: 'Product' })).toBeNull()
  })
})
