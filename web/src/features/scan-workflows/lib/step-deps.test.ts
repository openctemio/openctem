import { describe, expect, it } from 'vitest'
import type { ScanWorkflowStep } from '@/lib/api'
import { canRunAfter, moveToStageOf, setRunsAfter, stageLabels } from './step-deps'
import { planStages } from './workflow-stages'
import type { Capability, CapabilityTable } from './capability-graph'
import { applyLegacyFix, legacyCapabilityFix } from './step-capability'

const s = (
  key: string,
  deps: string[] = [],
  extra: Partial<ScanWorkflowStep> = {}
): ScanWorkflowStep => ({
  id: key,
  step_key: key,
  name: key.toUpperCase(),
  order: 1,
  ui_position: { x: 0, y: 0 },
  capabilities: [],
  depends_on: deps,
  max_retries: 0,
  retry_delay_seconds: 0,
  ...extra,
})

// Full Reconnaissance: subs -> (http, ports) -> vulns
const recon = () => [
  s('subs'),
  s('http', ['subs']),
  s('ports', ['subs']),
  s('vulns', ['http', 'ports']),
]

describe('runs after', () => {
  it('stages come from the dependencies; parallel steps are numbered 2a, 2b', () => {
    const labels = stageLabels(planStages(recon()))
    expect(labels).toEqual({ subs: '1', http: '2a', ports: '2b', vulns: '3' })
  })

  it('a step cannot run after itself or after a step that waits for it', () => {
    const steps = recon()
    expect(canRunAfter(steps, 'subs', 'subs')).toBe(false)
    expect(canRunAfter(steps, 'subs', 'vulns')).toBe(false) // vulns waits for subs through http
    expect(canRunAfter(steps, 'ports', 'http')).toBe(true)
  })

  it('setting runs-after drops a choice that would make a loop', () => {
    const next = setRunsAfter(recon(), 'subs', ['vulns', 'ports'])
    expect(next.find((x) => x.id === 'subs')?.depends_on).toEqual([])
    const chain = setRunsAfter(recon(), 'ports', ['subs', 'http'])
    expect(chain.find((x) => x.id === 'ports')?.depends_on).toEqual(['subs', 'http'])
    expect(stageLabels(planStages(chain))).toMatchObject({ http: '2', ports: '3', vulns: '4' })
  })

  it('dragging a step onto another stage gives it that stage’s dependencies', () => {
    // vulns moved next to http: it now runs after subs, in parallel with http.
    const r = moveToStageOf(recon(), 'vulns', 'http')
    expect(r.error).toBeUndefined()
    expect(r.steps.find((x) => x.id === 'vulns')?.depends_on).toEqual(['subs'])
    // subs moved next to vulns would wait for steps that wait for it: refused.
    const loop = moveToStageOf(recon(), 'subs', 'vulns')
    expect(loop.error).toMatch(/loop/)
    expect(loop.steps).toEqual(recon())
  })
})

describe('steps in the old format', () => {
  const cap = (key: string, tools: string[]): Capability => ({
    key,
    id: `${key}@1`,
    name: key,
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
      cap('discover.subdomains', ['subfinder']),
      cap('sca.deps', ['trivy']),
      cap('container.image', ['trivy']),
    ],
    adapters: [],
    portLabels: {},
  }

  it('a pinned tool with its old words offers the capability its tool implements', () => {
    const legacy = s('subs', [], { tool: 'subfinder', capabilities: ['recon', 'subdomain'] })
    const fix = legacyCapabilityFix(table, legacy)
    expect(fix.map((c) => c.key)).toEqual(['discover.subdomains'])
    expect(applyLegacyFix(legacy, fix[0])).toMatchObject({
      tool: 'subfinder',
      capabilities: ['discover.subdomains'],
    })
  })

  it('offers the choice when the tool implements several; nothing for new-format or unknown tools', () => {
    expect(
      legacyCapabilityFix(table, s('t', [], { tool: 'trivy', capabilities: ['sca'] }))
    ).toHaveLength(2)
    expect(
      legacyCapabilityFix(
        table,
        s('n', [], { tool: 'subfinder', capabilities: ['discover.subdomains'] })
      )
    ).toEqual([])
    expect(
      legacyCapabilityFix(table, s('c', [], { tool: 'my-scanner', capabilities: ['web'] }))
    ).toEqual([])
    expect(
      legacyCapabilityFix(table, s('a', [], { capabilities: ['discover.subdomains'] }))
    ).toEqual([])
  })
})
