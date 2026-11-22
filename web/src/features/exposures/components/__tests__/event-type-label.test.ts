import { describe, expect, it } from 'vitest'

import { exposureEventTypeLabel } from '../exposure-table'

// A translator that has the Vietnamese name of one type only, like a catalog.
const vi = (key: string, fallback?: string) =>
  key === 'exposures.eventType.credential_leaked' ? 'Lộ thông tin xác thực' : (fallback ?? key)

describe('exposureEventTypeLabel', () => {
  it('uses the catalog name in the reader language', () => {
    expect(exposureEventTypeLabel(vi, 'credential_leaked')).toBe('Lộ thông tin xác thực')
  })

  it('falls back to the English name of a known type', () => {
    expect(exposureEventTypeLabel(vi, 'dns_change')).toBe('DNS change')
  })

  it('reads an unknown type id as words', () => {
    expect(exposureEventTypeLabel(vi, 'brand_new_kind')).toBe('Brand new kind')
  })
})
