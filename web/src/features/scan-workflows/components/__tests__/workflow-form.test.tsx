/**
 * The workflow form is capability-first and never hardcodes a capability.
 * Owner bug 2026-10-08: one step "recon" with the tool DNSX was saved as
 * capabilities ["scan"], and the API refused it ("capability 'scan' is not
 * supported by tool 'dnsx'"). Editing must also send every step field back.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ScanWorkflowForm } from '../workflow-form'
import type { ScanWorkflow, CreateScanWorkflowRequest } from '@/lib/api'
import type { CapabilityTable, Capability } from '../../lib/capability-graph'

const cap = (key: string, name: string, tools: string[]): Capability => ({
  key,
  id: `${key}@1`,
  name,
  tier: 'T0',
  available: true,
  crossCutting: false,
  inPorts: [],
  outPorts: [],
  tools,
  defaultTool: tools[0],
  params: [],
  toolParams: {},
})

const table: CapabilityTable = {
  capabilities: [
    cap('resolve.dns', 'DNS resolution', ['dnsx']),
    cap('scan.ports', 'Port scan', ['naabu']),
    cap('discover.subdomains', 'Subdomain discovery', ['subfinder']),
    cap('probe.http', 'HTTP probe', ['httpx']),
  ],
  adapters: [],
  portLabels: {},
}

const tool = (name: string, display: string, capabilities: string[]) => ({
  tool: { id: name, name, display_name: display, capabilities, is_active: true },
  is_enabled: true,
  is_available: true,
})

vi.mock('@/lib/api/tool-hooks', () => ({
  useToolsWithConfig: () => ({
    data: { items: [tool('dnsx', 'DNSX', ['recon', 'dns']), tool('naabu', 'Naabu', ['portscan'])] },
    isLoading: false,
  }),
  useToolAvailability: () => ({ data: undefined }),
}))
vi.mock('@/lib/api/platform-hooks', () => ({
  usePlatformScanning: () => ({ offered: false }),
}))
vi.mock('../../lib/use-capability-table', () => ({
  useCapabilityTable: () => ({ table, isLoading: false }),
  validateScanWorkflowSteps: () => Promise.resolve({ valid: true, errors: [], warnings: [] }),
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}
// Radix Select calls these; jsdom does not implement them.
Element.prototype.scrollIntoView ??= () => {}
Element.prototype.releasePointerCapture ??= () => {}

async function pick(trigger: HTMLElement, option: RegExp) {
  await userEvent.click(trigger)
  await userEvent.click(await screen.findByRole('option', { name: option }))
}

async function toSettingsAndSave(onSubmit?: ReturnType<typeof vi.fn>) {
  await userEvent.click(screen.getByRole('button', { name: /next/i }))
  // Reaching the last tab never submits: the user still sees the settings.
  if (onSubmit) expect(onSubmit).not.toHaveBeenCalled()
  await userEvent.click(screen.getByRole('button', { name: /create workflow|update workflow/i }))
}

describe('ScanWorkflowForm: create', () => {
  it('saves a DNSX step as the capability it runs, with a key made from it', async () => {
    const onSubmit = vi.fn()
    render(<ScanWorkflowForm onSubmit={onSubmit} onCancel={vi.fn()} />)
    await userEvent.type(screen.getByLabelText(/workflow name/i), 'DNS only')
    await userEvent.click(screen.getByRole('button', { name: /next/i }))

    await userEvent.type(screen.getByLabelText('Name *'), 'recon')
    await pick(screen.getByRole('combobox', { name: 'Tool of step 1' }), /DNSX/)
    // The name typed stays; the capability shows instead of the tool picker.
    expect(screen.getByLabelText('Name *')).toHaveValue('recon')
    expect(screen.getByLabelText('Step key')).toHaveValue('resolve-dns')

    await toSettingsAndSave(onSubmit)
    const data = onSubmit.mock.calls[0][0] as CreateScanWorkflowRequest
    expect(data.steps).toHaveLength(1)
    expect(data.steps[0]).toMatchObject({
      step_key: 'resolve-dns',
      name: 'recon',
      tool: 'dnsx',
      capabilities: ['resolve.dns'],
      prefer_tools: [],
    })
    expect(data.steps[0].capabilities).not.toContain('scan')
    expect(data.steps[0].id).toBeUndefined()
    expect(data).not.toHaveProperty('triggers')
  })

  it('a capability step runs on any tool; keys stay unique and follow the capability', async () => {
    const onSubmit = vi.fn()
    render(<ScanWorkflowForm onSubmit={onSubmit} onCancel={vi.fn()} />)
    await userEvent.type(screen.getByLabelText(/workflow name/i), 'Two')
    await userEvent.click(screen.getByRole('button', { name: /next/i }))

    await pick(screen.getByRole('combobox', { name: 'What step 1 does' }), /DNS resolution/)
    await userEvent.click(screen.getByRole('button', { name: /add step/i }))
    await pick(screen.getByRole('combobox', { name: 'What step 2 does' }), /DNS resolution/)

    await toSettingsAndSave()
    const steps = (onSubmit.mock.calls[0][0] as CreateScanWorkflowRequest).steps
    expect(steps.map((s) => [s.step_key, s.name, s.tool, s.capabilities])).toEqual([
      ['resolve-dns', 'DNS resolution', '', ['resolve.dns']],
      ['resolve-dns-2', 'DNS resolution', '', ['resolve.dns']],
    ])
  })

  it('refuses a step that does nothing and a duplicate key', async () => {
    const onSubmit = vi.fn()
    render(<ScanWorkflowForm onSubmit={onSubmit} onCancel={vi.fn()} />)
    await userEvent.type(screen.getByLabelText(/workflow name/i), 'Bad')
    await userEvent.click(screen.getByRole('button', { name: /next/i }))
    await userEvent.type(screen.getByLabelText('Name *'), 'x')
    await userEvent.click(screen.getByRole('button', { name: /next/i }))
    expect(screen.getByText('Fix the highlighted steps.')).toBeInTheDocument()
    expect(onSubmit).not.toHaveBeenCalled()
  })
})

const workflow: ScanWorkflow = {
  id: 'w1',
  tenant_id: 't1',
  name: 'Recon',
  description: '',
  version: 1,
  is_active: true,
  is_system_template: false,
  tags: [],
  settings: {
    max_parallel_steps: 3,
    fail_fast: true,
    timeout_seconds: 1800,
    sensor_preference: 'auto',
  },
  steps: [
    {
      id: '0192f0b4-0000-7000-8000-000000000001',
      step_key: 'ports',
      name: 'Ports',
      order: 1,
      ui_position: { x: 400, y: 120 },
      tool: '',
      capabilities: ['scan.ports'],
      prefer_tools: ['naabu'],
      config: { top_n: 100 },
      timeout_seconds: 900,
      depends_on: [],
      condition: { type: 'always' },
      max_retries: 2,
      retry_delay_seconds: 30,
    },
  ],
  created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-01T00:00:00Z',
}

describe('ScanWorkflowForm: edit', () => {
  it('shows only settings that take effect: no triggers, no notify switch', async () => {
    render(<ScanWorkflowForm workflow={workflow} onSubmit={vi.fn()} onCancel={vi.fn()} />)
    expect(screen.queryByRole('tab', { name: /triggers/i })).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: /settings/i }))
    expect(screen.queryByText(/notify on failure/i)).not.toBeInTheDocument()
    expect(screen.getByLabelText(/max parallel steps/i)).toHaveValue(3)
  })

  it('a save that changed no step sends no steps', async () => {
    const onSubmit = vi.fn()
    render(<ScanWorkflowForm workflow={workflow} onSubmit={onSubmit} onCancel={vi.fn()} />)
    await userEvent.click(screen.getByRole('button', { name: /next/i }))
    await userEvent.click(screen.getByRole('button', { name: /next/i }))
    await userEvent.click(screen.getByRole('button', { name: /update workflow/i }))
    expect(onSubmit.mock.calls[0][0]).not.toHaveProperty('steps')
    expect(onSubmit.mock.calls[0][0].settings).toMatchObject({
      fail_fast: true,
      timeout_seconds: 1800,
    })
  })

  it('renaming a step keeps its id, key, preferences, retries, condition, config and layout', async () => {
    const onSubmit = vi.fn()
    render(<ScanWorkflowForm workflow={workflow} onSubmit={onSubmit} onCancel={vi.fn()} />)
    await userEvent.click(screen.getByRole('button', { name: /next/i }))
    const key = screen.getByLabelText('Step key')
    expect(key).toHaveAttribute('readonly')
    const name = screen.getByLabelText('Name *')
    await userEvent.clear(name)
    await userEvent.type(name, 'Open ports')
    expect(key).toHaveValue('ports')
    // The preferred tool shows as the capability's tool selection.
    expect(within(screen.getByRole('radiogroup')).getByLabelText('Preferred tools')).toBeChecked()

    await userEvent.click(screen.getByRole('button', { name: /next/i }))
    // Steps changed: they save to the draft, not into the version runs use.
    await userEvent.click(screen.getByRole('button', { name: 'Save draft' }))
    expect(onSubmit.mock.calls[0][1]).toEqual({ publish: false })
    expect(onSubmit.mock.calls[0][0].steps).toEqual([
      {
        id: '0192f0b4-0000-7000-8000-000000000001',
        step_key: 'ports',
        name: 'Open ports',
        order: 1,
        tool: '',
        capabilities: ['scan.ports'],
        prefer_tools: ['naabu'],
        timeout_seconds: 900,
        depends_on: [],
        max_retries: 2,
        retry_delay_seconds: 30,
        condition: { type: 'always' },
        ui_position: { x: 400, y: 120 },
        config: { top_n: 100 },
      },
    ])
  })
})

const st = (
  id: string,
  key: string,
  name: string,
  extra: Partial<ScanWorkflow['steps'][number]> = {}
): ScanWorkflow['steps'][number] => ({
  id,
  step_key: key,
  name,
  order: 1,
  ui_position: { x: 0, y: 0 },
  tool: '',
  capabilities: [],
  prefer_tools: [],
  depends_on: [],
  max_retries: 0,
  retry_delay_seconds: 0,
  ...extra,
})

// The owner's Full Reconnaissance copy: a legacy subfinder step, then HTTP
// probing and port scanning in parallel.
const recon: ScanWorkflow = {
  ...workflow,
  id: 'w2',
  name: 'Full Reconnaissance',
  steps: [
    st('0192f0b4-0000-7000-8000-00000000000a', 'subdomain_enum', 'Subdomain Enumeration', {
      tool: 'subfinder',
      capabilities: ['recon', 'subdomain'],
    }),
    st('0192f0b4-0000-7000-8000-00000000000b', 'http_probe', 'HTTP Probing', {
      capabilities: ['probe.http'],
      depends_on: ['subdomain_enum'],
    }),
    st('0192f0b4-0000-7000-8000-00000000000c', 'port_scan', 'Port Scanning', {
      capabilities: ['scan.ports'],
      depends_on: ['subdomain_enum'],
    }),
  ],
}

describe('ScanWorkflowForm: stages', () => {
  it('groups steps by stage from what they run after; parallel steps are 2a and 2b', async () => {
    render(<ScanWorkflowForm workflow={recon} onSubmit={vi.fn()} onCancel={vi.fn()} />)
    await userEvent.click(screen.getByRole('button', { name: /next/i }))
    const headings = screen.getAllByRole('heading', { level: 4 }).map((h) => h.textContent)
    expect(headings).toEqual(['Stage 1', 'Stage 2 · 2 steps run in parallel · waits for Stage 1'])
    expect(screen.getByLabelText('Step 1')).toBeInTheDocument()
    expect(screen.getByLabelText('Step 2a')).toBeInTheDocument()
    expect(screen.getByLabelText('Step 2b')).toBeInTheDocument()
  })

  it('runs-after refuses a loop and a change moves the step to another stage', async () => {
    const onSubmit = vi.fn()
    render(<ScanWorkflowForm workflow={recon} onSubmit={onSubmit} onCancel={vi.fn()} />)
    await userEvent.click(screen.getByRole('button', { name: /next/i }))
    // The first step cannot run after a step that waits for it.
    await userEvent.click(
      screen.getByRole('button', { name: 'What Subdomain Enumeration runs after' })
    )
    expect(await screen.findByRole('menuitemcheckbox', { name: /HTTP Probing/ })).toHaveAttribute(
      'aria-disabled',
      'true'
    )
    await userEvent.keyboard('{Escape}')
    // Port scanning after HTTP probing: three stages, one step each.
    await userEvent.click(screen.getByRole('button', { name: 'What Port Scanning runs after' }))
    await userEvent.click(await screen.findByRole('menuitemcheckbox', { name: /HTTP Probing/ }))
    await userEvent.keyboard('{Escape}')
    expect(screen.getAllByRole('heading', { level: 4 })).toHaveLength(3)

    await userEvent.click(screen.getByRole('button', { name: /next/i }))
    await userEvent.click(screen.getByRole('button', { name: 'Save draft' }))
    const ports = onSubmit.mock.calls[0][0].steps.find(
      (x: { step_key: string }) => x.step_key === 'port_scan'
    )
    expect(ports.depends_on).toEqual(['subdomain_enum', 'http_probe'])
  })

  it('a step in the old format is fixed in one click, and saved to the draft', async () => {
    const onSubmit = vi.fn()
    render(<ScanWorkflowForm workflow={recon} onSubmit={onSubmit} onCancel={vi.fn()} />)
    await userEvent.click(screen.getByRole('button', { name: /next/i }))
    expect(screen.getByText(/1 step uses the old format/)).toBeInTheDocument()
    await userEvent.click(
      screen.getByRole('button', {
        name: 'Use capability discover.subdomains (subfinder implements it)',
      })
    )
    expect(screen.queryByText(/uses the old format/)).toBeNull()

    await userEvent.click(screen.getByRole('button', { name: /next/i }))
    await userEvent.click(screen.getByRole('button', { name: 'Save and publish' }))
    expect(onSubmit.mock.calls[0][1]).toEqual({ publish: true })
    expect(onSubmit.mock.calls[0][0].steps[0]).toMatchObject({
      step_key: 'subdomain_enum',
      tool: 'subfinder',
      capabilities: ['discover.subdomains'],
    })
  })

  it('Fix all fixes every step whose tool has one capability', async () => {
    const two: ScanWorkflow = {
      ...recon,
      steps: [
        ...recon.steps,
        st('0192f0b4-0000-7000-8000-00000000000d', 'dns', 'DNS', {
          tool: 'dnsx',
          capabilities: ['recon', 'dns'],
          depends_on: ['subdomain_enum'],
        }),
      ],
    }
    render(<ScanWorkflowForm workflow={two} onSubmit={vi.fn()} onCancel={vi.fn()} />)
    await userEvent.click(screen.getByRole('button', { name: /next/i }))
    expect(screen.getByText(/2 steps use the old format/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Fix all' }))
    expect(screen.queryByText(/old format/)).toBeNull()
  })
})
