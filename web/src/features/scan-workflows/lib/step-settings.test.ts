import { describe, expect, it } from 'vitest'
import type { ScanWorkflowStep } from '@/lib/api'
import type { Capability } from './capability-graph'
import {
  paramValue,
  selectionOf,
  standardOnly,
  toolsMissingParams,
  withParam,
  withSelection,
} from './step-settings'

const ports: Capability = {
  key: 'scan.ports',
  id: 'scan.ports@1',
  name: 'Port scan',
  tier: 'T1',
  available: true,
  crossCutting: false,
  inPorts: ['hostname', 'ip'],
  outPorts: ['service', 'ip'],
  tools: ['naabu', 'masscan'],
  defaultTool: 'naabu',
  params: [
    { name: 'ports', type: 'port_list', description: 'Ports', enum: [] },
    { name: 'top_n', type: 'integer', description: 'Top N', enum: [], min: 1, max: 65535 },
    { name: 'protocol', type: 'string', description: 'Protocol', enum: ['tcp'] },
    { name: 'rate', type: 'integer', description: 'Rate', enum: [], min: 1, max: 100000 },
  ],
  toolParams: {
    naabu: { ports: 'ports', top_n: 'top_ports', rate: 'rate' },
    masscan: { ports: 'ports' },
  },
}

function step(over: Partial<ScanWorkflowStep> = {}): ScanWorkflowStep {
  return {
    id: 's1',
    step_key: 'ports',
    name: 'Ports',
    order: 1,
    ui_position: { x: 0, y: 0 },
    capabilities: ['scan.ports'],
    max_retries: 0,
    retry_delay_seconds: 0,
    ...over,
  }
}

describe('selection', () => {
  it('derives the mode as the API does', () => {
    expect(selectionOf(step())).toBe('auto')
    expect(selectionOf(step({ prefer_tools: ['masscan'] }))).toBe('prefer')
    expect(selectionOf(step({ tool: 'naabu', prefer_tools: [] }))).toBe('pin')
  })

  it('pin sets the tool and clears the prefer list', () => {
    const s = withSelection(step({ prefer_tools: ['masscan'] }), ports, 'pin', ['naabu'])
    expect(s.tool).toBe('naabu')
    expect(s.prefer_tools).toEqual([])
    expect(s.capabilities).toEqual(['scan.ports'])
  })

  it('prefer keeps only implementations, in order', () => {
    const s = withSelection(step(), ports, 'prefer', ['masscan', 'nuclei', 'naabu'])
    expect(s.tool).toBe('')
    expect(s.prefer_tools).toEqual(['masscan', 'naabu'])
  })

  it('leaving pin drops the pinned tool settings, keeps the standard params', () => {
    const pinned = step({
      tool: 'naabu',
      config: { rate: 10, exclude_cdn: true, x: { naabu: {} }, exclude: ['a'] },
    })
    const s = withSelection(pinned, ports, 'auto', [])
    expect(s.config).toEqual({ rate: 10, exclude: ['a'] })
    expect(standardOnly(undefined, ports)).toBeUndefined()
  })
})

describe('paramValue: only contract values get in', () => {
  const p = (name: string) => ports.params.find((x) => x.name === name)!

  it('integers within bounds', () => {
    expect(paramValue(p('rate'), '500')).toEqual({ value: 500 })
    expect(paramValue(p('rate'), '0').error).toBeTruthy()
    expect(paramValue(p('rate'), '100001').error).toBeTruthy()
    expect(paramValue(p('rate'), '1.5').error).toBeTruthy()
    expect(paramValue(p('rate'), '')).toEqual({ value: undefined })
  })

  it('port lists never look like a flag', () => {
    expect(paramValue(p('ports'), '80, 443,8000-8100')).toEqual({ value: '80,443,8000-8100' })
    expect(paramValue(p('ports'), '-p-').error).toBeTruthy()
    expect(paramValue(p('ports'), '80;id').error).toBeTruthy()
  })

  it('enums are closed', () => {
    expect(paramValue(p('protocol'), 'tcp')).toEqual({ value: 'tcp' })
    expect(paramValue(p('protocol'), 'udp').error).toBeTruthy()
    const sev = {
      name: 'severity',
      type: 'string_list' as const,
      description: '',
      enum: ['high', 'critical'],
    }
    expect(paramValue(sev, ['high'])).toEqual({ value: ['high'] })
    expect(paramValue(sev, 'high, urgent').error).toBeTruthy()
  })

  it('booleans', () => {
    const b = { name: 'recursive', type: 'boolean' as const, description: '', enum: [] }
    expect(paramValue(b, true)).toEqual({ value: true })
    expect(paramValue(b, false)).toEqual({ value: false })
  })
})

describe('config editing', () => {
  it('sets and clears one param', () => {
    expect(withParam({ a: 1 }, 'rate', 5)).toEqual({ a: 1, rate: 5 })
    expect(withParam({ a: 1, rate: 5 }, 'rate', undefined)).toEqual({ a: 1 })
  })

  it('names the tools that cannot run the node with its settings', () => {
    expect(toolsMissingParams(ports, { top_n: 100, ports: '80' })).toEqual({ masscan: ['top_n'] })
    expect(toolsMissingParams(ports, {})).toEqual({})
  })
})
