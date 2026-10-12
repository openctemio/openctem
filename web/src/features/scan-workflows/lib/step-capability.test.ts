import { describe, expect, it } from 'vitest'
import type { ScanWorkflowStep } from '@/lib/api'
import type { Capability, CapabilityTable } from './capability-graph'
import { capabilitiesOfTool, namedCapability, withCapability, withTool } from './step-capability'
import { toStepRequest, roundPosition } from './step-request'

const cap = (
  key: string,
  name: string,
  tools: string[],
  extra: Partial<Capability> = {}
): Capability => ({
  key,
  id: `${key}@1`,
  name,
  tier: 'T0',
  available: true,
  crossCutting: false,
  inPorts: [],
  outPorts: [],
  tools,
  defaultTool: tools[0] ?? '',
  params: [],
  toolParams: {},
  ...extra,
})

const table: CapabilityTable = {
  capabilities: [
    cap('resolve.dns', 'DNS resolution', ['dnsx']),
    cap('scan.ports', 'Port scan', ['naabu']),
    cap('sca.deps', 'Dependency scan', ['trivy', 'grype']),
    cap('container.image', 'Container image scan', ['trivy', 'grype']),
    cap('verify.finding', 'Verify', ['nuclei'], { crossCutting: true }),
    cap('check.tls', 'TLS', [], { available: false }),
  ],
  adapters: [],
  portLabels: {},
}

const base: ScanWorkflowStep = {
  id: 'temp-1',
  step_key: 'step',
  name: '',
  order: 1,
  ui_position: { x: 0, y: 0 },
  tool: '',
  capabilities: [],
  prefer_tools: [],
  max_retries: 0,
  retry_delay_seconds: 0,
}

describe('capability-first steps', () => {
  it('a tool that runs one capability gives the step that capability, never "scan"', () => {
    // The owner's bug: dnsx in the form was saved with capabilities ["scan"].
    const r = withTool(table, base, 'dnsx', ['recon', 'dns'])
    expect(r.choose).toEqual([])
    expect(r.step.tool).toBe('dnsx')
    expect(r.step.capabilities).toEqual(['resolve.dns'])
    expect(toStepRequest(r.step, 0)).toMatchObject({
      tool: 'dnsx',
      capabilities: ['resolve.dns'],
    })
  })

  it('a tool that runs several capabilities asks which one', () => {
    const r = withTool(table, base, 'trivy', ['sca', 'container'])
    expect(r.step.tool).toBe('trivy')
    expect(r.step.capabilities).toEqual([])
    expect(r.choose.map((c) => c.key)).toEqual(['sca.deps', 'container.image'])
    // Already on one of them: kept, nothing to ask.
    const kept = withTool(table, { ...base, capabilities: ['container.image'] }, 'trivy', [])
    expect(kept.choose).toEqual([])
    expect(kept.step.capabilities).toEqual(['container.image'])
  })

  it('a tool the catalog does not know keeps its own declared words', () => {
    const r = withTool(table, base, 'my-scanner', ['web', 'dast'])
    expect(r.step.capabilities).toEqual(['web', 'dast'])
    expect(r.choose).toEqual([])
  })

  it('picking a capability keeps a pin only when the tool implements it', () => {
    const dns = table.capabilities[0]
    const ports = table.capabilities[1]
    const pinned = { ...base, tool: 'dnsx', capabilities: ['resolve.dns'] }
    expect(withCapability(pinned, dns)).toMatchObject({
      tool: 'dnsx',
      capabilities: ['resolve.dns'],
    })
    expect(withCapability(pinned, ports)).toMatchObject({ tool: '', capabilities: ['scan.ports'] })
    expect(withCapability({ ...base, prefer_tools: ['dnsx'] }, ports).prefer_tools).toEqual([])
  })

  it('only routed, non-cross-cutting capabilities are offered', () => {
    expect(capabilitiesOfTool(table, 'nuclei')).toEqual([])
    expect(namedCapability(table, { capabilities: ['check.tls'] })).toBeNull()
    expect(namedCapability(table, { capabilities: ['RESOLVE.DNS'] })?.key).toBe('resolve.dns')
  })
})

describe('toStepRequest round trip', () => {
  it('sends every field back: id, preferences, retries, condition, config, layout', () => {
    const saved: ScanWorkflowStep = {
      id: '0192f0b4-0000-7000-8000-000000000001',
      step_key: 'scan-ports',
      name: 'Ports',
      description: 'top ports',
      order: 3,
      ui_position: { x: -307.4222108759977, y: 120.6 },
      tool: '',
      capabilities: ['scan.ports'],
      prefer_tools: ['naabu'],
      config: { top_n: 100 },
      timeout_seconds: 900,
      depends_on: ['resolve-dns'],
      condition: { type: 'step_result', value: 'resolve-dns' },
      max_retries: 2,
      retry_delay_seconds: 30,
    }
    expect(toStepRequest(saved, 0)).toEqual({
      id: saved.id,
      step_key: 'scan-ports',
      name: 'Ports',
      description: 'top ports',
      order: 1,
      tool: '',
      capabilities: ['scan.ports'],
      prefer_tools: ['naabu'],
      timeout_seconds: 900,
      depends_on: ['resolve-dns'],
      max_retries: 2,
      retry_delay_seconds: 30,
      condition: { type: 'step_result', value: 'resolve-dns' },
      ui_position: { x: -307, y: 121 },
      config: { top_n: 100 },
    })
  })

  it('a new step sends no temporary id; a pinned step sends no preferences', () => {
    const r = toStepRequest({ ...base, tool: 'dnsx', prefer_tools: ['x'] }, 1)
    expect(r.id).toBeUndefined()
    expect(r.prefer_tools).toEqual([])
    expect(r.order).toBe(2)
  })

  it('drops a position that is not finite', () => {
    expect(roundPosition({ x: Number.NaN, y: 1 })).toBeUndefined()
    expect(roundPosition({ x: 1.4, y: -0.6 })).toEqual({ x: 1, y: -1 })
  })
})
