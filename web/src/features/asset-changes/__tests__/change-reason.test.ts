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
  'matched by host_id',
  'matched by repo_suffix',
  'newer_observation: decided by scan source nuclei, observed 2026-11-20T08:00:00Z',
  'ttl_expiry: decided by integration source -, observed 2026-11-20T08:00:00Z',
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

  it('reads a rename match and a decided value back into words', () => {
    expect(changeReasonLabel('matched by host_id', tEn)).toBe('Matched by its host ID')
    expect(changeReasonLabel('matched by mac', tVi)).toBe('Khớp theo địa chỉ MAC')
    const en = changeReasonLabel(
      'newer_observation: decided by scan source nuclei, observed 2026-11-20T08:00:00Z',
      tEn,
      'en'
    )
    expect(en).toMatch(/^Newer report: decided by scan nuclei, seen /)
    expect(en).not.toContain('2026-11-20T08')
    const vi = changeReasonLabel(
      'ttl_expiry: decided by integration source -, observed 2026-11-20T08:00:00Z',
      tVi,
      'vi'
    )
    expect(vi).toMatch(/^Nguồn đã quá hạn: do tích hợp quyết định, thấy lúc /)
    expect(vi).not.toMatch(/decided|observed|ttl_expiry/)
  })

  it('shows an unknown identifier kind or reason code as written', () => {
    expect(changeReasonLabel('matched by something_new', tEn)).toBe('Matched by something new')
    expect(
      changeReasonLabel('odd_code: decided by scan source x, observed 2026-11-20T08:00:00Z', tEn)
    ).toBe('Odd code: decided by scan source x, observed 2026-11-20T08:00:00Z')
  })

  it('reads English without a translator and shows an unknown reason as written', () => {
    expect(changeReasonLabel('asset created')).toBe('Asset created')
    expect(changeReasonLabel('merged_into_other')).toBe('Merged into other')
    expect(changeReasonLabel('')).toBe('—')
    expect(changeReasonLabel(undefined)).toBe('—')
  })
})
