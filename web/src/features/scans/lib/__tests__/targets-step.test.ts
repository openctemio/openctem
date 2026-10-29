import { describe, expect, it } from 'vitest'
import { enTranslate } from '../translate'
import { lowerIntensityAllowed, targetOptionsSummary, targetsNextBlock } from '../targets-step'
import { isFormDirty } from '../form-dirty'
import { DEFAULT_NEW_SCAN } from '../../types'

const r = (
  state: 'unknown' | 'ready' | 'partial' | 'blocked',
  refused = 0,
  unresolved: string[] = []
) => ({
  state,
  scannable: state === 'blocked' ? 0 : 1,
  refused,
  unresolved,
})

describe('targetsNextBlock', () => {
  it('lets the wizard go on unless every target is blocked', () => {
    expect(targetsNextBlock(r('unknown'), enTranslate)).toBeNull()
    expect(targetsNextBlock(r('ready'), enTranslate)).toBeNull()
    // Some ready: Next proceeds, the Review step lists what is skipped.
    expect(targetsNextBlock(r('partial', 3), enTranslate)).toBeNull()
  })

  it('says why Next is disabled when nothing can run', () => {
    expect(targetsNextBlock(r('blocked', 1), enTranslate)).toBe(
      'Fix or remove the blocked target to continue.'
    )
    expect(targetsNextBlock(r('blocked', 2, ['a.example']), enTranslate)).toBe(
      'Fix or remove the 3 blocked targets to continue.'
    )
    expect(targetsNextBlock(r('blocked', 0, ['a.example', 'b.example']), enTranslate)).toBe(
      'None of these 2 names resolve in DNS. Fix their records or remove them to continue.'
    )
  })
})

describe('lowerIntensityAllowed', () => {
  const activeWorkflow = [{ tool: 'httpx' }]
  it('offers a lower intensity only for a workflow that still fits it', () => {
    const form = { mode: 'workflow', intensity: 'intrusive' as const }
    expect(lowerIntensityAllowed(form, activeWorkflow, 1)).toBe(true)
    // The workflow has an intrusive step: lowering would drop it.
    expect(lowerIntensityAllowed(form, [{ tool: 'zap' }], 1)).toBe(false)
    // Not lower than the current intensity.
    expect(lowerIntensityAllowed({ ...form, intensity: 'active' }, activeWorkflow, 1)).toBe(false)
  })

  it('never for a single scanner or an unloaded workflow', () => {
    expect(
      lowerIntensityAllowed({ mode: 'single', intensity: 'intrusive' }, activeWorkflow, 1)
    ).toBe(false)
    expect(lowerIntensityAllowed({ mode: 'workflow', intensity: 'intrusive' }, undefined, 1)).toBe(
      false
    )
  })
})

describe('targetOptionsSummary', () => {
  it('summarises the options on one line, comma separated, no middle dot', () => {
    const s = targetOptionsSummary(enTranslate, {
      coverage: 'subdomains',
      targets: ['*.example.com', '10.0.0.0/24'],
      options: { cidr_mode: 'inventory', include_unresolved: true },
    })
    expect(s).toContain('Host and its subdomains')
    expect(s).toContain('names that do not resolve included')
    expect(s).not.toMatch(/·/)
    expect(s.split(', ').length).toBeGreaterThanOrEqual(3)
  })

  it('is empty when there is nothing to summarise', () => {
    expect(targetOptionsSummary(enTranslate, { targets: ['a.example'], options: undefined })).toBe(
      ''
    )
  })
})

describe('isFormDirty', () => {
  it('ignores display-only names and the coverage expansion', () => {
    const loaded = { ...DEFAULT_NEW_SCAN, name: 'x' }
    const named = {
      ...loaded,
      targets: {
        ...loaded.targets,
        assetGroupNames: { g1: 'Group' },
        expandedTargets: ['1.2.3.4'],
      },
    }
    expect(isFormDirty(named, loaded)).toBe(false)
    const edited = { ...loaded, targets: { ...loaded.targets, customTargets: ['a.example'] } }
    expect(isFormDirty(edited, loaded)).toBe(true)
  })
})
