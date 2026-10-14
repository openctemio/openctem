import { describe, expect, it } from 'vitest'

import { getDictionary, translate } from '@/lib/i18n'

import { DEFAULT_TAB_ORDER } from '../source-layout'

// The finding's data-flow tab shows the source-to-sink trace, not an attack
// path. Its label says so; its key stays `attack-path` so `?tab=attack-path`
// links keep opening it.
describe('finding data-flow tab', () => {
  it('keeps the attack-path tab key', () => {
    expect(DEFAULT_TAB_ORDER).toContain('attack-path')
  })

  it('is labelled Data flow in English and Luồng dữ liệu in Vietnamese', () => {
    expect(translate(getDictionary('en'), 'findings.detail.tab.attack-path')).toBe('Data flow')
    expect(translate(getDictionary('vi'), 'findings.detail.tab.attack-path')).toBe('Luồng dữ liệu')
  })
})
