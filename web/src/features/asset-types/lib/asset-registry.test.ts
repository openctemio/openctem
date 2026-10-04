import { describe, expect, it } from 'vitest'
import {
  classAndLensLabel,
  classLabel,
  classOfAsset,
  lensLabel,
  lensOfClass,
  type AssetTypeRegistry,
} from './asset-registry'
import { ASSET_CLASSES, ASSET_LENSES, ASSET_TYPE_CLASSES } from '../registry.generated'

// A trimmed response of GET /api/v1/asset-types.
const served: AssetTypeRegistry = {
  version: 'test',
  lenses: [
    { id: 'code', label: 'Code (served)' },
    { id: 'cloud_infra', label: 'Cloud & infrastructure' },
  ],
  classes: [
    { id: 'code_repo', label: 'Code repository (served)', lens: 'code' },
    { id: 'host', label: 'Host', lens: 'cloud_infra' },
    { id: 'function', label: 'Function', lens: 'cloud_infra' },
    { id: 'other', label: 'Other' },
  ],
  types: [
    { type: 'repository', class: 'code_repo', lens: 'code' },
    { type: 'host', class: 'host', lens: 'cloud_infra' },
    {
      type: 'serverless',
      class: 'function',
      lens: 'cloud_infra',
      alias_of: { type: 'host', sub_type: 'serverless' },
    },
  ],
}

describe('asset registry lookups', () => {
  it('uses the served registry when it has loaded', () => {
    expect(classOfAsset(served, 'repository')).toBe('code_repo')
    expect(classLabel(served, 'code_repo')).toBe('Code repository (served)')
    expect(lensLabel(served, 'code')).toBe('Code (served)')
    expect(classAndLensLabel(served, 'repository')).toBe('Code repository (served) · Code (served)')
  })

  it('keeps an alias in its own class', () => {
    expect(classOfAsset(served, 'host', 'serverless')).toBe('function')
    expect(classOfAsset(served, 'host', 'compute')).toBe('host')
    expect(classOfAsset(undefined, 'host', 'serverless')).toBe('function')
    expect(classOfAsset(undefined, 'storage', 'container_registry')).toBe('artifact_registry')
    expect(classOfAsset(undefined, 'service', 'discovered_url')).toBe('web_endpoint')
  })

  it('falls back to the generated constants before the registry loads', () => {
    expect(classOfAsset(undefined, 'repository')).toBe('code_repo')
    expect(classAndLensLabel(undefined, 'repository')).toBe('Code repository · Code')
    expect(classAndLensLabel(undefined, 'kubernetes', 'cluster')).toBe(
      'Cluster · Containers & Kubernetes'
    )
  })

  it('puts unknown and unclassified types in class other, with no lens', () => {
    expect(classOfAsset(served, 'no_such_type')).toBe('other')
    expect(classOfAsset(undefined, 'unclassified')).toBe('other')
    expect(lensOfClass(undefined, 'other')).toBeNull()
    expect(classAndLensLabel(undefined, 'unclassified')).toBe('Other')
  })

  it('generated constants are consistent: every class but other has a lens', () => {
    expect(ASSET_LENSES).toHaveLength(8)
    expect(ASSET_CLASSES.filter((c) => c.id !== 'other')).toHaveLength(16)
    for (const c of ASSET_CLASSES) {
      if (c.id === 'other') expect(c.lens).toBeNull()
      else expect(ASSET_LENSES.find((l) => l.id === c.lens)?.classes).toContain(c.id)
    }
    // 36 types + unclassified; web_application is an input name only (O3)
    expect(Object.keys(ASSET_TYPE_CLASSES)).toHaveLength(37)
  })
})
