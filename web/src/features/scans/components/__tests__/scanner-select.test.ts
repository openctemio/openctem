import { describe, expect, it } from 'vitest'

import type { Tool } from '@/lib/api/tool-types'
import { scannerOptions } from '../scanner-select'

const tool = (over: Partial<Tool>) =>
  ({ id: over.name, name: 'x', display_name: '', is_active: true, ...over }) as Tool

describe('scannerOptions', () => {
  it('offers active scanners only, never collectors, sorted by label', () => {
    const out = scannerOptions([
      tool({ name: 'trivy', display_name: 'Trivy' }),
      tool({ name: 'old', display_name: 'Old', is_active: false }),
      tool({
        name: 'cloud-inventory',
        display_name: 'Cloud inventory',
        metadata: { kind: 'collector' },
      }),
      tool({ name: 'nuclei', display_name: 'Nuclei' }),
      tool({ name: 'semgrep', display_name: '' }),
    ])
    expect(out.map((t) => t.name)).toEqual(['nuclei', 'semgrep', 'trivy'])
  })

  it('offers a connector scanner only when asked (the wizard, while the connector is on)', () => {
    const tools = [
      tool({ name: 'nuclei', display_name: 'Nuclei' }),
      tool({
        name: 'tenable_sc',
        display_name: 'Tenable Security Center',
        metadata: { kind: 'connector' },
      }),
    ]
    expect(scannerOptions(tools).map((t) => t.name)).toEqual(['nuclei'])
    expect(scannerOptions(tools, true).map((t) => t.name)).toEqual(['nuclei', 'tenable_sc'])
  })

  it('is empty without data', () => {
    expect(scannerOptions(undefined)).toEqual([])
  })
})
