import { describe, expect, it } from 'vitest'

import {
  ALL_FINDING_SOURCES,
  CODE_SOURCES,
  MISCONFIG_SOURCES,
  SECRET_SOURCES,
  VULNERABILITY_SOURCES,
} from '../type-sources'

describe('exposure type sources', () => {
  it('vulnerabilities is every source except sast, iac, secret and cspm', () => {
    expect(VULNERABILITY_SOURCES).not.toContain('sast')
    expect(VULNERABILITY_SOURCES).not.toContain('iac')
    expect(VULNERABILITY_SOURCES).not.toContain('secret')
    expect(VULNERABILITY_SOURCES).not.toContain('cspm')
    for (const s of ['va', 'container', 'easm', 'external', 'threat_intel', 'sca', 'dast']) {
      expect(VULNERABILITY_SOURCES).toContain(s)
    }
  })

  it('misconfigurations is iac and cspm', () => {
    expect([...MISCONFIG_SOURCES].sort()).toEqual(['cspm', 'iac'])
  })

  it('the four pages partition every source exactly once', () => {
    const all = [...CODE_SOURCES, ...SECRET_SOURCES, ...MISCONFIG_SOURCES, ...VULNERABILITY_SOURCES]
    expect([...all].sort()).toEqual([...ALL_FINDING_SOURCES].sort())
    expect(new Set(all).size).toBe(all.length)
  })
})
