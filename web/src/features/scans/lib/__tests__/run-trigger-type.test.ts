import { describe, expect, it } from 'vitest'
import { translate } from '@/lib/i18n'
import { vi as viDict } from '@/lib/i18n/dictionaries/vi'
import { SCAN_RUN_TRIGGERS } from '@/lib/api/scan-workflow-types'
import { runTriggerTypeLabel } from '../run-display'

const tVi = (key: string, fallback?: string) => translate(viDict, key, fallback, undefined, 'vi')

describe('runTriggerTypeLabel', () => {
  it('words every run trigger type from the catalog', () => {
    for (const type of SCAN_RUN_TRIGGERS) {
      const label = runTriggerTypeLabel(type, tVi)
      expect(label, type).not.toMatch(/^scans\./)
      expect(label, type).not.toBe(type)
    }
    expect(runTriggerTypeLabel('manual', tVi)).toBe('Thủ công')
  })

  it('reads English by default and shows an unknown type as sent', () => {
    expect(runTriggerTypeLabel('manual')).toBe('Manual')
    expect(runTriggerTypeLabel('ci_pipeline')).toBe('ci_pipeline')
    expect(runTriggerTypeLabel(undefined)).toBe('')
  })
})
