import { describe, expect, it } from 'vitest'
import type { ScanWorkflowStep } from '@/lib/api'
import { makeIsValidConnection, wouldCreateCycle } from '@/components/flow/connection-rules'
import {
  capabilityForStep,
  checkStepConnection,
  insertAdapterStep,
  issuesForStep,
  stepEdges,
  toCapabilityTable,
  type ScanStageList,
} from './capability-graph'

// A slice of GET /api/v1/scans/stages, as the API serves it.
const served: ScanStageList = {
  max_hops: 3,
  port_types: [
    { type: 'root_domain', label: 'Root domain', carries: ['domain'] },
    { type: 'hostname', label: 'Hostname', carries: ['domain', 'subdomain'] },
    { type: 'ip', label: 'IP address', carries: ['ip_address', 'host'] },
    { type: 'service', label: 'Service (host:port)', carries: ['service/open_port'] },
    { type: 'url', label: 'URL', carries: ['service/http'] },
    { type: 'finding', label: 'Finding', carries: [] },
  ],
  adapters: [
    { from: 'hostname', to: 'url', capability: 'probe.http' },
    { from: 'hostname', to: 'ip', capability: 'resolve.dns' },
  ],
  stages: [
    {
      key: 'discover.subdomains',
      id: 'discover.subdomains@1',
      name: 'Subdomain discovery',
      tier: 'T0',
      available: true,
      in_ports: ['root_domain'],
      out_ports: ['hostname'],
      implementations: [{ tool: 'subfinder', default: true }],
    },
    {
      key: 'probe.http',
      id: 'probe.http@1',
      name: 'HTTP probe',
      tier: 'T1',
      available: true,
      in_ports: ['hostname', 'ip', 'service', 'url'],
      out_ports: ['url', 'ip'],
      implementations: [{ tool: 'httpx', default: true }],
    },
    {
      key: 'crawl.web',
      id: 'crawl.web@1',
      name: 'Web crawl',
      tier: 'T1',
      available: true,
      in_ports: ['url'],
      out_ports: ['url'],
      implementations: [{ tool: 'katana', default: true }],
    },
    {
      key: 'vuln.templates',
      id: 'vuln.templates@1',
      name: 'Vulnerability templates',
      tier: 'T1',
      available: true,
      in_ports: ['url', 'service', 'hostname', 'ip'],
      out_ports: ['finding'],
      implementations: [{ tool: 'nuclei', default: true }],
    },
    {
      key: 'dast.web',
      id: 'dast.web@1',
      name: 'Web application scan',
      tier: 'T2',
      available: true,
      in_ports: ['url'],
      out_ports: ['finding'],
      implementations: [{ tool: 'zap', default: true }],
    },
    {
      key: 'check.tls',
      id: 'check.tls@1',
      name: 'TLS check',
      tier: 'T1',
      available: false,
      in_ports: ['service', 'url'],
      out_ports: ['finding'],
      implementations: [],
    },
  ],
}
const table = toCapabilityTable(served)

function step(
  id: string,
  tool: string,
  depends: string[] = [],
  caps: string[] = []
): ScanWorkflowStep {
  return {
    id,
    step_key: id,
    name: id,
    order: 1,
    ui_position: { x: 0, y: 0 },
    tool,
    capabilities: caps,
    depends_on: depends,
    max_retries: 0,
    retry_delay_seconds: 0,
  }
}

describe('capabilityForStep', () => {
  it('places a step by its tool, then by its capability words', () => {
    expect(capabilityForStep(table, step('a', 'subfinder'))?.key).toBe('discover.subdomains')
    expect(capabilityForStep(table, step('a', '', [], ['crawl.web']))?.key).toBe('crawl.web')
  })
  it('has no contract for a tenant tool or a planned capability', () => {
    expect(capabilityForStep(table, step('a', 'my-scanner', [], ['scan']))).toBeNull()
    expect(capabilityForStep(table, step('a', 'tlsx'))).toBeNull()
  })
})

describe('checkStepConnection', () => {
  const steps = [
    step('subs', 'subfinder'),
    step('crawl', 'katana'),
    step('http', 'httpx'),
    step('custom', 'my-scanner'),
  ]

  it('refuses hostnames into a URL crawler, with a plain reason and the adapter', () => {
    const v = checkStepConnection(table, steps, [], 'subs', 'crawl')
    expect(v.ok).toBe(false)
    if (v.ok) return
    expect(v.reason).toContain('crawl takes URL')
    expect(v.reason).toContain('subs gives Hostname')
    expect(v.reason).toContain('Insert HTTP probe')
    expect(v.adapter).toBe('probe.http')
  })

  it('accepts compatible ports', () => {
    expect(checkStepConnection(table, steps, [], 'subs', 'http').ok).toBe(true)
    expect(checkStepConnection(table, steps, [], 'http', 'crawl').ok).toBe(true)
  })

  it('allows a step without a contract, with a warning that no data passes', () => {
    const v = checkStepConnection(table, steps, [], 'http', 'custom')
    expect(v).toMatchObject({ ok: true })
    expect(v.ok && v.warning).toContain('passes no data')
  })

  it('refuses a loop', () => {
    const edges = stepEdges([step('subs', 'subfinder'), step('http', 'httpx', ['subs'])])
    const v = checkStepConnection(table, steps, edges, 'http', 'subs')
    expect(v.ok).toBe(false)
  })

  it('never feeds an intrusive (T2) step', () => {
    const v = checkStepConnection(table, [...steps, step('zap', 'zap')], [], 'http', 'zap')
    expect(v.ok).toBe(false)
  })
})

describe('insertAdapterStep', () => {
  it('turns a refused connection into a valid chain', () => {
    const steps = [step('subs', 'subfinder'), step('crawl', 'katana')]
    const next = insertAdapterStep(table, steps, 'subs', 'crawl', 'probe.http')
    expect(next).toHaveLength(3)
    const adapter = next[2]
    // A capability node with any tool, never a pinned tool that may be missing.
    expect(adapter.tool).toBe('')
    expect(adapter.capabilities).toEqual(['probe.http'])
    expect(adapter.step_key).toBe('probe-http')
    expect(adapter.id.startsWith('temp-')).toBe(true)
    expect(adapter.depends_on).toEqual(['subs'])
    const crawl = next.find((s) => s.id === 'crawl')!
    expect(crawl.depends_on).toEqual([adapter.step_key])
    // Every edge of the result is valid.
    const edges = stepEdges(next)
    for (const e of edges) {
      const others = edges.filter((x) => x !== e)
      expect(checkStepConnection(table, next, others, e.source, e.target).ok).toBe(true)
    }
  })

  it('changes nothing for an unknown capability', () => {
    const steps = [step('subs', 'subfinder'), step('crawl', 'katana')]
    expect(insertAdapterStep(table, steps, 'subs', 'crawl', 'nope')).toBe(steps)
  })
})

describe('flow kit', () => {
  it('detects cycles', () => {
    const edges = [
      { source: 'a', target: 'b' },
      { source: 'b', target: 'c' },
    ]
    expect(wouldCreateCycle(edges, 'c', 'a')).toBe(true)
    expect(wouldCreateCycle(edges, 'a', 'c')).toBe(false)
    expect(wouldCreateCycle([], 'a', 'a')).toBe(true)
  })

  it('isValidConnection keeps the last refusal to explain it', () => {
    const rule = makeIsValidConnection((s, t) =>
      s === 'x' ? { ok: false, reason: `no ${t}`, adapter: 'probe.http' } : { ok: true }
    )
    expect(rule.isValidConnection({ source: 'x', target: 'y' })).toBe(false)
    expect(rule.lastRefusal()).toMatchObject({ reason: 'no y', adapter: 'probe.http' })
    expect(rule.isValidConnection({ source: 'a', target: 'y' })).toBe(true)
    expect(rule.lastRefusal()).toBeNull()
    expect(rule.isValidConnection({ source: null, target: 'y' })).toBe(false)
  })
})

describe('issuesForStep', () => {
  it('collects node issues and edge issues pointing at the step', () => {
    const report = {
      valid: false,
      errors: [
        { code: 'INCOMPATIBLE_PORTS', message: 'm1', from: 'subs', to: 'crawl' },
        { code: 'UNKNOWN_CAPABILITY', message: 'm2', node: 'crawl' },
        { code: 'CYCLE', message: 'm3', node: 'other' },
      ],
      warnings: [],
    }
    expect(issuesForStep(report, 'crawl').map((i) => i.message)).toEqual(['m1', 'm2'])
    expect(issuesForStep(null, 'crawl')).toEqual([])
  })
})
