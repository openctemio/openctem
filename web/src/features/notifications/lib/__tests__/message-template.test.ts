import { describe, it, expect } from 'vitest'
import { TEMPLATE_PRESETS, TEMPLATE_VARIABLES, detailLevelOf, presetOf } from '../message-template'

describe('message template settings', () => {
  it('presets use only the closed variable set', () => {
    for (const p of TEMPLATE_PRESETS) {
      for (const m of (p.template ?? '').matchAll(/\{([a-z_]+)\}/g)) {
        expect(TEMPLATE_VARIABLES as readonly string[]).toContain(m[1])
      }
    }
  })

  it('never offers a rendered-output placeholder', () => {
    const all = TEMPLATE_PRESETS.map((p) => p.template ?? '').join('\n')
    for (const gone of ['severity_emoji', 'url', 'body', 'timestamp']) {
      expect(all).not.toContain(`{${gone}}`)
    }
  })

  it('maps stored templates to presets', () => {
    expect(presetOf('')).toBe('default')
    expect(presetOf(undefined)).toBe('default')
    expect(presetOf('{asset}: {what}\n{next_step}')).toBe('short')
    expect(presetOf('{title} on {asset}')).toBe('custom')
  })

  it('reads unknown levels as standard', () => {
    expect(detailLevelOf('minimal')).toBe('minimal')
    expect(detailLevelOf(undefined)).toBe('standard')
    expect(detailLevelOf('everything')).toBe('standard')
  })
})
