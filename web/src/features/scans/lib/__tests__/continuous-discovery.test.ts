import { describe, expect, it } from 'vitest'
import type { ScanWorkflow } from '@/lib/api/scan-workflow-types'
import { continuousDiscoveryPair, probeNewAssetsRequest } from '../continuous-discovery'

const wf = (id: string, tags: string[]) => ({ id, name: id, tags }) as unknown as ScanWorkflow

describe('continuous discovery', () => {
  it('needs both starter workflows', () => {
    expect(continuousDiscoveryPair([wf('p', ['starter', 'passive'])])).toBeNull()
    const pair = continuousDiscoveryPair([wf('p', ['passive']), wf('n', ['continuous'])])
    expect(pair?.passive.id).toBe('p')
    expect(pair?.probe.id).toBe('n')
  })

  it('probes only assets new since the last run, actively, under the same roots', () => {
    const req = probeNewAssetsRequest(
      {
        name: 'Acme',
        scan_type: 'workflow',
        scan_workflow_id: 'p',
        intensity: 'passive',
        targets: ['example.com', '*.acme.io', '203.0.113.7'],
        asset_group_ids: ['g'],
        schedule_type: 'daily',
      },
      'n',
      'Acme: new assets'
    )
    expect(req).toMatchObject({
      name: 'Acme: new assets',
      intensity: 'active',
      scan_workflow_id: 'n',
      targets: ['*.example.com', '*.acme.io'],
      target_options: { new_since_last_run: true },
      schedule_type: 'daily',
    })
    expect(req?.asset_group_ids).toBeUndefined()
  })

  it('has nothing to probe without a domain', () => {
    expect(
      probeNewAssetsRequest(
        { name: 'x', scan_type: 'workflow', targets: ['203.0.113.7'] },
        'n',
        'y'
      )
    ).toBeNull()
  })
})
