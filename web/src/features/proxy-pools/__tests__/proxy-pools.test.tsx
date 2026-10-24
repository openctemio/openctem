import { beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'

import { ApiClientError } from '@/lib/api/error-handler'
import { TooltipProvider } from '@/components/ui/tooltip'

import { endpointUrl, maskPasteText } from '../lib/mask'
import type { ProxyPool } from '../types'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver
// Radix Select uses pointer capture and scrollIntoView, which jsdom lacks.
Element.prototype.hasPointerCapture ??= () => false
Element.prototype.releasePointerCapture ??= () => {}
Element.prototype.scrollIntoView ??= () => {}

let pools: ProxyPool[] = []
let assignments: { sensor_id: string; mode: string; pool_id?: string }[] = []
const saveEndpoints = vi.fn()
const createPool = vi.fn()
const deletePool = vi.fn()
const setAssignment = vi.fn()
const patchEndpoint = vi.fn()

let poolsError: unknown
let assignmentsPending = false
const poolsMutate = vi.fn()
const assignmentsMutate = vi.fn()
const updatePool = vi.fn().mockResolvedValue({})
vi.mock('../api/use-proxy-pools', () => ({
  useProxyPools: () => ({
    data: poolsError ? undefined : { items: pools },
    isLoading: false,
    error: poolsError,
    mutate: poolsMutate,
  }),
  useProxyAssignments: () => ({
    data: assignmentsPending ? undefined : { items: assignments },
    isLoading: assignmentsPending,
    error: undefined,
    mutate: assignmentsMutate,
  }),
  invalidateProxyPools: vi.fn(),
  createProxyPool: (...a: unknown[]) => createPool(...a),
  updateProxyPool: (...a: unknown[]) => updatePool(...a),
  deleteProxyPool: (...a: unknown[]) => deletePool(...a),
  saveProxyEndpoints: (...a: unknown[]) => saveEndpoints(...a),
  updateProxyEndpoint: (...a: unknown[]) => patchEndpoint(...a),
  setProxyAssignment: (...a: unknown[]) => setAssignment(...a),
}))

let perms: string[] = []
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: (p: string) => perms.includes(p), isLoading: false }),
  useHasPermission: (p: string) => perms.includes(p),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

import { ProxyPoolsPanel } from '../components/proxy-pools-panel'
import { SensorNetworkPathSection, pathRequest } from '../components/sensor-network-path-section'

const ALL = ['sensors:egress:read', 'sensors:egress:write', 'sensors:egress:delete']

function pool(over: Partial<ProxyPool> = {}): ProxyPool {
  return {
    id: 'p1',
    name: 'Corp egress',
    description: '',
    enabled: true,
    is_default: true,
    strategy: 'sticky',
    revision: 3,
    assigned_sensors: 0,
    created_at: '2026-10-01T00:00:00Z',
    updated_at: '2026-10-01T00:00:00Z',
    endpoints_text: 'socks5://••••@10.0.0.5:1080#dc1\nhttp://proxy.corp.example:3128',
    endpoints: [
      {
        id: 'e1',
        scheme: 'socks5',
        host: '10.0.0.5',
        port: 1080,
        label: 'dc1',
        priority: 0,
        enabled: true,
        has_credentials: true,
        health: {
          state: 'quarantined',
          score: 0.42,
          consecutive_failures: 5,
          ok_total: 10,
          fail_total: 5,
          handshake_ms_p95: 120,
          last_error: 'proxy_down: connection refused',
          last_ok_at: '2026-10-01T00:00:00Z',
          last_failure_at: null,
          quarantined_until: '2026-10-21T10:00:00Z',
        },
      },
      {
        id: 'e2',
        scheme: 'http',
        host: 'proxy.corp.example',
        port: 3128,
        label: '',
        priority: 1,
        enabled: true,
        has_credentials: false,
        health: {
          state: 'healthy',
          score: 0.92,
          consecutive_failures: 0,
          ok_total: 1,
          fail_total: 0,
          handshake_ms_p95: 10,
          last_error: '',
          last_ok_at: null,
          last_failure_at: null,
          quarantined_until: null,
        },
      },
    ],
    ...over,
  }
}

function renderPanel() {
  return render(
    <TooltipProvider>
      <ProxyPoolsPanel />
    </TooltipProvider>
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  pools = [pool()]
  assignments = []
  perms = ALL
  poolsError = undefined
  assignmentsPending = false
})

describe('Proxies page', () => {
  it('shows stored lines as returned, masked, and never a credential', () => {
    renderPanel()
    const field = screen.getByTestId('proxy-paste-list') as HTMLTextAreaElement
    expect(field.value).toBe('socks5://••••@10.0.0.5:1080#dc1\nhttp://proxy.corp.example:3128')
    expect(screen.getAllByTestId('proxy-lock')).toHaveLength(1)
    expect(screen.getByText('socks5://10.0.0.5:1080')).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/user:pass|hunter2/)
  })

  it('masks userinfo even if a response carried real credentials', () => {
    pools = [pool({ endpoints_text: 'socks5://user:hunter2@10.0.0.5:1080#dc1' })]
    renderPanel()
    const field = screen.getByTestId('proxy-paste-list') as HTMLTextAreaElement
    expect(field.value).toBe('socks5://••••@10.0.0.5:1080#dc1')
    expect(document.body.innerHTML).not.toContain('hunter2')
    expect(maskPasteText('http://a:b@h:1')).toBe('http://••••@h:1')
    expect(maskPasteText('http://••••@h:1')).toBe('http://••••@h:1')
  })

  it('renders endpoint url without userinfo, state and quarantine', () => {
    expect(endpointUrl({ scheme: 'socks5', host: '::1', port: 1 })).toBe('socks5://[::1]:1')
    renderPanel()
    const rows = screen.getAllByTestId('proxy-endpoint-row')
    expect(rows).toHaveLength(2)
    expect(rows[0].textContent).toContain('Quarantined')
    expect(rows[0].textContent).toContain('until')
    expect(rows[0].textContent).toContain('42%')
    expect(rows[1].textContent).toContain('Healthy')
  })

  it('saves the pasted text with PUT endpoints', async () => {
    saveEndpoints.mockResolvedValue({})
    renderPanel()
    const field = screen.getByTestId('proxy-paste-list')
    fireEvent.change(field, { target: { value: 'socks5://••••@10.0.0.5:1080#dc1' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() =>
      expect(saveEndpoints).toHaveBeenCalledWith('p1', 'socks5://••••@10.0.0.5:1080#dc1')
    )
  })

  it('creates the default pool when none exists', async () => {
    pools = []
    createPool.mockResolvedValue({})
    renderPanel()
    fireEvent.click(screen.getByRole('switch', { name: 'Use proxies for scans' }))
    fireEvent.change(screen.getByTestId('proxy-paste-list'), {
      target: { value: 'socks5://u:p@10.0.0.9:1080' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() =>
      expect(createPool).toHaveBeenCalledWith({
        name: 'Organization default',
        is_default: true,
        enabled: true,
        endpoints_text: 'socks5://u:p@10.0.0.9:1080',
      })
    )
  })

  it('refuses to enable an empty pool (it would fail every scan closed)', async () => {
    pools = []
    renderPanel()
    fireEvent.click(screen.getByRole('switch', { name: 'Use proxies for scans' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByTestId('proxy-paste-error')).toHaveTextContent(
      'Add at least one proxy'
    )
    expect(createPool).not.toHaveBeenCalled()
  })

  it('shows the server validation error with its line inline', async () => {
    saveEndpoints.mockRejectedValue(
      new ApiClientError('line 2: host is not allowed', 'INVALID_PROXY_ENDPOINT', 400)
    )
    renderPanel()
    fireEvent.change(screen.getByTestId('proxy-paste-list'), {
      target: { value: 'socks5://localhost:1' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByTestId('proxy-paste-error')).toHaveTextContent(
      'line 2: host is not allowed'
    )
  })

  it('without write permission there is no textarea editing, save or row actions', () => {
    perms = ['sensors:egress:read']
    renderPanel()
    expect((screen.getByTestId('proxy-paste-list') as HTMLTextAreaElement).readOnly).toBe(true)
    expect(screen.queryByRole('button', { name: 'Save' })).toBeNull()
    expect(screen.queryByRole('button', { name: /Reset health/ })).toBeNull()
    expect(screen.getByRole('button', { name: 'New pool' })).toBeDisabled()
  })

  it('resets endpoint health with PATCH', async () => {
    patchEndpoint.mockResolvedValue({})
    renderPanel()
    fireEvent.click(screen.getAllByRole('button', { name: /Reset health/ })[0])
    await waitFor(() =>
      expect(patchEndpoint).toHaveBeenCalledWith('p1', 'e1', { reset_health: true })
    )
  })

  it('explains a pool that is still in use when delete answers 409', async () => {
    pools = [pool(), pool({ id: 'p2', name: 'Segment A', is_default: false })]
    deletePool.mockRejectedValue(new ApiClientError('pool in use', 'PROXY_POOL_IN_USE', 409))
    const { toast } = await import('sonner')
    renderPanel()
    fireEvent.click(screen.getByRole('button', { name: 'Delete Segment A' }))
    const confirm = await screen.findByRole('button', { name: 'Delete pool' })
    expect(confirm).toBeDisabled()
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'Segment A' } })
    fireEvent.click(confirm)
    await waitFor(() => expect(deletePool).toHaveBeenCalledWith('p2'))
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        expect.stringContaining('Sensors still use this pool')
      )
    )
  })

  it('disables Delete with a reason while sensors use the pool, and says "1 sensor"', () => {
    pools = [pool(), pool({ id: 'p2', name: 'Segment A', is_default: false, assigned_sensors: 1 })]
    renderPanel()
    expect(screen.getByRole('button', { name: 'Delete Segment A' })).toBeDisabled()
    expect(screen.getByLabelText(/Sensors still use this pool/)).toBeInTheDocument()
    expect(screen.getByText(/1 sensor assigned/)).toBeInTheDocument()
    expect(screen.queryByText(/1 sensors assigned/)).not.toBeInTheDocument()
  })

  it('does not toast when an endpoint is reset (the row updates in place)', async () => {
    patchEndpoint.mockResolvedValue({})
    const { toast } = await import('sonner')
    renderPanel()
    fireEvent.click(screen.getAllByRole('button', { name: /Reset health/ })[0])
    await waitFor(() => expect(patchEndpoint).toHaveBeenCalled())
    expect(toast.success).not.toHaveBeenCalled()
  })

  it('without delete permission the delete button is disabled', () => {
    perms = ['sensors:egress:read', 'sensors:egress:write']
    pools = [pool(), pool({ id: 'p2', name: 'Segment A', is_default: false })]
    renderPanel()
    expect(screen.getByRole('button', { name: /Delete Segment A|permission/ })).toBeDisabled()
  })
})

describe('New pool dialog', () => {
  function openNew() {
    renderPanel()
    fireEvent.click(screen.getByRole('button', { name: /New pool/ }))
  }

  it('blocks Save while the pool is enabled without a proxy', async () => {
    openNew()
    const dialog = within(await screen.findByRole('dialog'))
    fireEvent.change(dialog.getByLabelText('Name'), { target: { value: 'seg' } })
    expect(dialog.getByTestId('pool-needs-proxy')).toBeInTheDocument()
    expect(dialog.getByRole('button', { name: 'Save' })).toBeDisabled()
    fireEvent.click(dialog.getByLabelText('Enabled'))
    expect(dialog.queryByTestId('pool-needs-proxy')).not.toBeInTheDocument()
    expect(dialog.getByRole('button', { name: 'Save' })).toBeEnabled()
  })

  it('turns a pool off before emptying its list (the API refuses an enabled empty pool)', async () => {
    const order: string[] = []
    saveEndpoints.mockImplementation(async () => void order.push('list'))
    updatePool.mockImplementation(async () => void order.push('pool'))
    pools = [pool(), pool({ id: 'p2', name: 'Segment A', is_default: false })]
    renderPanel()
    fireEvent.click(screen.getByRole('button', { name: 'Edit' }))
    const dialog = within(await screen.findByRole('dialog'))
    fireEvent.change(dialog.getByTestId('proxy-paste-list'), { target: { value: '' } })
    fireEvent.click(dialog.getByLabelText('Enabled'))
    fireEvent.click(dialog.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(order).toEqual(['pool', 'list']))
  })
})

describe('Sensor network path', () => {
  function renderSection() {
    pools = [pool(), pool({ id: 'p2', name: 'Segment A', is_default: false })]
    return render(
      <TooltipProvider>
        <SensorNetworkPathSection sensorId="s1" />
      </TooltipProvider>
    )
  }
  const choose = async (name: RegExp | string) => {
    fireEvent.click(screen.getByRole('combobox'))
    fireEvent.click(await screen.findByRole('option', { name }))
  }

  it('maps the select to the assignment body', () => {
    expect(pathRequest('inherit')).toEqual({ mode: 'inherit' })
    expect(pathRequest('direct')).toEqual({ mode: 'direct' })
    expect(pathRequest('pool:p2')).toEqual({ mode: 'pool', pool_id: 'p2' })
  })

  it('sends the chosen pool for this sensor', async () => {
    setAssignment.mockResolvedValue({})
    renderSection()
    await choose('Segment A')
    await waitFor(() =>
      expect(setAssignment).toHaveBeenCalledWith('s1', { mode: 'pool', pool_id: 'p2' })
    )
  })

  it('does not toast a saved network path', async () => {
    setAssignment.mockResolvedValue({})
    const { toast } = await import('sonner')
    renderSection()
    await choose('Segment A')
    await waitFor(() => expect(setAssignment).toHaveBeenCalled())
    expect(toast.success).not.toHaveBeenCalled()
  })

  it('shows the stored assignment and is read-only without write', () => {
    assignments = [{ sensor_id: 's1', mode: 'direct' }]
    perms = ['sensors:egress:read']
    renderSection()
    const select = screen.getByRole('combobox')
    expect(select).toHaveTextContent('Direct')
    expect(select).toBeDisabled()
  })

  it('never shows "Inherit" when the pools request failed: an error with Retry, and no select', () => {
    assignments = [{ sensor_id: 's1', mode: 'direct' }]
    poolsError = new Error('boom')
    renderSection()
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument()
    expect(screen.queryByText(/Inherit/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(poolsMutate).toHaveBeenCalled()
    expect(assignmentsMutate).toHaveBeenCalled()
  })

  it('shows a skeleton, not "Inherit", while the assignments load', () => {
    assignmentsPending = true
    renderSection()
    expect(screen.getByTestId('network-path-skeleton')).toBeInTheDocument()
    expect(screen.queryByText(/Inherit/)).not.toBeInTheDocument()
  })

  it('asks before going direct while the organization default is on', async () => {
    setAssignment.mockResolvedValue({})
    renderSection()
    await choose('Direct')
    expect(await screen.findByText('Send this sensor direct?')).toBeInTheDocument()
    expect(setAssignment).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Go direct' }))
    await waitFor(() => expect(setAssignment).toHaveBeenCalledWith('s1', { mode: 'direct' }))
  })

  it('goes direct without asking when no default pool is on', async () => {
    setAssignment.mockResolvedValue({})
    pools = []
    render(
      <TooltipProvider>
        <SensorNetworkPathSection sensorId="s1" />
      </TooltipProvider>
    )
    await choose('Direct')
    await waitFor(() => expect(setAssignment).toHaveBeenCalledWith('s1', { mode: 'direct' }))
  })

  it('marks a disabled pool in the list', async () => {
    renderSection()
    pools = [pool(), pool({ id: 'p2', name: 'Segment A', is_default: false, enabled: false })]
    cleanup()
    render(
      <TooltipProvider>
        <SensorNetworkPathSection sensorId="s1" />
      </TooltipProvider>
    )
    fireEvent.click(screen.getByRole('combobox'))
    expect(await screen.findByRole('option', { name: 'Segment A (disabled)' })).toBeInTheDocument()
  })

  it('renders nothing without read permission', () => {
    perms = []
    const { container } = renderSection()
    expect(container.textContent).toBe('')
  })
})
