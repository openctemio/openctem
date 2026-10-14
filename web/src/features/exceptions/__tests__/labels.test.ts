import { describe, expect, it } from 'vitest'

import { getDictionary, translate, type TranslateVars } from '@/lib/i18n'

import {
  suppressionScopeSummary,
  suppressionStatusLabel,
  suppressionTypeLabel,
  type SuppressionRule,
} from '../types'

const viT = (key: string, fallback?: string, vars?: TranslateVars) =>
  translate(getDictionary('vi'), key, fallback, vars)

describe('suppression labels', () => {
  it('render English without a translator', () => {
    expect(suppressionTypeLabel('wont_fix')).toBe("Won't Fix")
    expect(suppressionStatusLabel('pending')).toBe('Pending')
  })

  it('render through the Vietnamese catalog', () => {
    expect(suppressionTypeLabel('false_positive', viT)).toBe('Dương tính giả')
    expect(suppressionStatusLabel('expired', viT)).toBe('Đã hết hạn')
    expect(suppressionScopeSummary({} as SuppressionRule, viT)).toBe('Mọi phát hiện')
  })
})
