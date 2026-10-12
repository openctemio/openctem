import { describe, expect, it } from 'vitest'
import {
  fitsIntensity,
  intensityForTier,
  stepTier,
  toolTier,
  workflowTier,
} from '../scan-intensity'

describe('scan intensity', () => {
  it('classifies scanners like the API catalog', () => {
    expect(toolTier('subfinder')).toBe(0)
    expect(toolTier('dnsx')).toBe(0)
    expect(toolTier('httpx')).toBe(1)
    expect(toolTier('zap')).toBe(2)
    expect(toolTier('something-new')).toBe(1) // unknown is never passive
  })

  it('takes the highest tier among a workflow’s steps', () => {
    const passive = [{ capabilities: ['discover.subdomains'] }, { capabilities: ['resolve.dns'] }]
    expect(workflowTier(passive)).toBe(0)
    expect(workflowTier([...passive, { capabilities: ['probe.http'] }])).toBe(1)
    expect(workflowTier([{ tool: 'zap', capabilities: [] }])).toBe(2)
    expect(workflowTier([])).toBe(1)
  })

  it('counts a DNS step with custom resolvers as active', () => {
    expect(stepTier({ tool: 'dnsx' })).toBe(0)
    expect(stepTier({ tool: 'dnsx', config: { resolvers: ['203.0.113.53'] } })).toBe(1)
    expect(stepTier({ capabilities: ['resolve.dns'], config: { resolvers: [] } })).toBe(0)
  })

  it('filters by the ceiling', () => {
    expect(fitsIntensity(0, 'passive')).toBe(true)
    expect(fitsIntensity(1, 'passive')).toBe(false)
    expect(fitsIntensity(1, 'active')).toBe(true)
    expect(fitsIntensity(2, 'active')).toBe(false)
    expect(fitsIntensity(2, 'intrusive')).toBe(true)
    expect(intensityForTier(2)).toBe('intrusive')
  })
})
