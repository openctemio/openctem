import { describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { Sensor, SensorManifestVersion } from '@/lib/api/sensor-types'

const manifests = vi.hoisted(() => ({
  value: {
    data: undefined as { items: SensorManifestVersion[] } | undefined,
    error: undefined as unknown,
    isLoading: false,
  },
}))
vi.mock('@/lib/api/sensor-hooks', () => ({
  useSensorManifests: () => ({ ...manifests.value, mutate: vi.fn() }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn() } }))

import { SensorManifestTab } from '../sensor-manifest-tab'

const sensor = { id: 's1', name: 'scanner' } as Sensor
const at = new Date(Date.now() - 3600_000).toISOString()

function version(digest: string, nucleiVersion: string, current: boolean): SensorManifestVersion {
  return {
    digest,
    source: 'sensor',
    current,
    manifest: {
      schema: 1,
      sensor: { name: 'openctemio-sensor', version: '0.6.4' },
      sdk: { name: 'openctem-sdk-go', version: '0.15.0' },
      platform: { os: 'linux', arch: 'amd64' },
      resources: { cpu_cores: 4, mem_total_bytes: 8 * 1024 ** 3 },
      concurrency: { ceiling: 0, model: 'dynamic' },
      capabilities: ['validate'],
      tools: [
        {
          name: 'nuclei',
          kind: 'scanner',
          version: nucleiVersion,
          installed: true,
          capabilities: ['dast', 'validate:nuclei'],
          content: [{ name: 'nuclei-templates', version: 'v10.4.9', managed: true }],
        },
      ],
    },
    ignored: current ? [{ path: 'tools[1]', value: 'zap2', reason: 'unknown-tool' }] : [],
    first_seen_at: at,
    current_since: at,
    last_seen_at: at,
  }
}

describe('SensorManifestTab', () => {
  it('shows the current manifest, what was ignored and the history with its diff', async () => {
    const items = [
      version(`sha256:${'b'.repeat(64)}`, 'v3.12.0', true),
      version(`sha256:${'a'.repeat(64)}`, 'v3.11.1', false),
    ]
    manifests.value = { data: { items }, error: undefined, isLoading: false }
    render(<SensorManifestTab sensor={sensor} now={Date.now()} />)

    expect(screen.getByText('registered by the sensor · current since 1h ago')).toBeInTheDocument()
    expect(screen.getByText(/^4 CPU cores · .+ memory$/)).toBeInTheDocument()
    expect(
      screen.getByText('no operator cap · slots sized from CPU and memory')
    ).toBeInTheDocument()
    const tools = screen.getByRole('list', { name: 'Manifest tools' })
    expect(within(tools).getByLabelText('nuclei capabilities')).toHaveTextContent(
      'dastvalidate:nuclei'
    )
    expect(within(tools).getByText('nuclei-templates v10.4.9')).toBeInTheDocument()
    expect(screen.getByRole('note')).toHaveTextContent('"zap2": not in the tool catalog')

    const history = screen.getByRole('list', { name: 'Manifest versions' })
    expect(within(history).getByText('nuclei v3.11.1 → v3.12.0')).toBeInTheDocument()
    expect(within(history).getByText('First version kept.')).toBeInTheDocument()
    expect(within(history).getByText('current')).toBeInTheDocument()

    await userEvent.click(screen.getAllByRole('button', { name: /Copy manifest digest/ })[0])
  })

  it("shows a ported tool's contract and a contract change in the history", async () => {
    const contract = (digest: string) => ({
      api_version: 'openctem.io/tool/v1',
      digest,
      version: '1.0.0',
      class: 'target-scan',
      tier: 'T1',
      network: 'targets',
      consumes: ['domain', 'http_service'],
      produces: ['asset:http_service', 'asset:certificate'],
    })
    const withContract = (v: SensorManifestVersion, digest: string): SensorManifestVersion => ({
      ...v,
      manifest: {
        ...v.manifest,
        tools: v.manifest.tools.map((t) => ({ ...t, contract: contract(digest) })),
      },
    })
    const newC = `sha256:${'d'.repeat(64)}`
    const oldC = `sha256:${'c'.repeat(64)}`
    const items = [
      withContract(version(`sha256:${'b'.repeat(64)}`, 'v3.12.0', true), newC),
      withContract(version(`sha256:${'a'.repeat(64)}`, 'v3.12.0', false), oldC),
    ]
    manifests.value = { data: { items }, error: undefined, isLoading: false }
    render(<SensorManifestTab sensor={sensor} now={Date.now()} />)

    const block = screen.getByLabelText('nuclei tool contract')
    expect(block).toHaveTextContent('target-scan · T1 · network: targets')
    expect(block).toHaveTextContent('v1.0.0')
    expect(block).toHaveTextContent('Consumesdomainhttp_service')
    expect(block).toHaveTextContent('Producesasset:http_serviceasset:certificate')
    expect(
      within(block).getByRole('button', { name: `Copy tool contract digest ${newC}` })
    ).toBeInTheDocument()

    const history = screen.getByRole('list', { name: 'Manifest versions' })
    expect(
      within(history).getByText('nuclei tool contract sha256:cccccccccccc → sha256:dddddddddddd')
    ).toBeInTheDocument()
  })

  it('names an ignored invalid tool contract', () => {
    const v = version(`sha256:${'b'.repeat(64)}`, 'v3.12.0', true)
    v.ignored = [
      { path: 'tools[0].contract', value: 'invalid produces entry', reason: 'invalid-contract' },
    ]
    manifests.value = { data: { items: [v] }, error: undefined, isLoading: false }
    render(<SensorManifestTab sensor={sensor} now={Date.now()} />)
    expect(screen.getByRole('note')).toHaveTextContent(
      '"invalid produces entry": not a valid tool contract'
    )
    expect(screen.queryByLabelText('nuclei tool contract')).not.toBeInTheDocument()
  })

  it('says when there is no manifest yet', () => {
    manifests.value = { data: { items: [] }, error: undefined, isLoading: false }
    render(<SensorManifestTab sensor={sensor} now={Date.now()} />)
    expect(screen.getByText(/No manifest yet/)).toBeInTheDocument()
  })

  it('shows a load error in place', () => {
    manifests.value = { data: undefined, error: new Error('boom'), isLoading: false }
    render(<SensorManifestTab sensor={sensor} now={Date.now()} />)
    expect(screen.getByRole('alert')).toHaveTextContent('The manifest could not be loaded.')
  })
})
