import { describe, expect, it } from 'vitest'
import { translate } from '@/lib/i18n'
import { vi as viDict } from '@/lib/i18n/dictionaries/vi'
import { en as enDict } from '@/lib/i18n/dictionaries/en'
import { changeReasonLabel } from '../lib/change-reason'

const tVi = (key: string, fallback?: string, vars?: Record<string, string | number>) =>
  translate(viDict, key, fallback, vars, 'vi')
const tEn = (key: string, fallback?: string, vars?: Record<string, string | number>) =>
  translate(enDict, key, fallback, vars, 'en')

// Every reason the server writes for an asset state change
// (server/internal/app/asset, server/internal/app/ingest).
const SERVER_REASONS = [
  'asset created',
  'discovered by scan',
  're-observed by scan',
  'not seen by any scan within the stale threshold',
  'not in the latest complete report of collector edge-collector',
]

describe('changeReasonLabel', () => {
  it('words every server reason from the catalog in Vietnamese', () => {
    for (const reason of SERVER_REASONS) {
      const vi = changeReasonLabel(reason, tVi)
      expect(vi, reason).not.toBe(changeReasonLabel(reason, tEn))
    }
    expect(changeReasonLabel('asset created', tVi)).toBe('Đã tạo tài sản')
  })

  it('keeps the collector name', () => {
    expect(
      changeReasonLabel('not in the latest complete report of collector edge-collector', tEn)
    ).toBe('Not in the latest full report of edge-collector')
  })

  it('reads English without a translator and shows an unknown reason as written', () => {
    expect(changeReasonLabel('asset created')).toBe('Asset created')
    expect(changeReasonLabel('merged_into_other')).toBe('Merged into other')
    expect(changeReasonLabel('')).toBe('—')
    expect(changeReasonLabel(undefined)).toBe('—')
  })
})
