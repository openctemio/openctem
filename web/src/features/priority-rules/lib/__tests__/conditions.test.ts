import { describe, expect, it } from 'vitest'

import { en, vi } from '@/lib/i18n/dictionaries'
import { describeCondition, type Condition } from '../conditions'

function translator(locale: 'en' | 'vi') {
  const dict: Record<string, string> = locale === 'vi' ? vi : en
  return (key: string, fallback?: string, vars?: Record<string, string | number>) => {
    let s = dict[key] ?? fallback ?? key
    for (const [k, v] of Object.entries(vars ?? {})) s = s.replaceAll(`{${k}}`, String(v))
    return s
  }
}

const cases: [Condition, string, string][] = [
  [{ field: 'is_in_kev', operator: 'eq', value: true }, 'Listed in KEV', 'Có trong danh mục KEV'],
  [
    { field: 'is_in_kev', operator: 'neq', value: true },
    'Not listed in KEV',
    'Không có trong danh mục KEV',
  ],
  [{ field: 'is_reachable', operator: 'eq', value: false }, 'Not reachable', 'Không truy cập được'],
  [
    { field: 'epss_score', operator: 'gte', value: 0.5 },
    'EPSS score is at least 50%',
    'Điểm EPSS từ 50% trở lên',
  ],
  [
    { field: 'asset_exposure', operator: 'eq', value: 'private' },
    'Asset exposure is Private',
    'Mức độ phơi nhiễm của tài sản là Riêng tư',
  ],
  [
    { field: 'severity', operator: 'in', value: ['critical', 'high'] },
    'Severity is Critical or High',
    'Mức độ nghiêm trọng là Nghiêm trọng hoặc Cao',
  ],
]

describe('describeCondition', () => {
  it.each(cases)('%o reads as a sentence in en and vi', (c, en, vi) => {
    expect(describeCondition(c, translator('en'), 'en')).toBe(en)
    expect(describeCondition(c, translator('vi'), 'vi')).toBe(vi)
  })

  it('shows a field this build does not know without dropping it', () => {
    const c = { field: 'new_field', operator: 'eq', value: 'x' } as unknown as Condition
    expect(describeCondition(c, translator('en'), 'en')).toBe('new_field is x')
  })
})
