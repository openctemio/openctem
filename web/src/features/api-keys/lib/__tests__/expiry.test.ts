import { describe, expect, it } from 'vitest'

import { API_KEY_EXPIRY_OPTIONS, DEFAULT_API_KEY_EXPIRY_DAYS, expiryOptionsFor } from '../expiry'

describe('API key lifetimes', () => {
  it('offers only what the API accepts (1 to 365 days), never "never"', () => {
    for (const o of API_KEY_EXPIRY_OPTIONS) {
      const days = Number(o.value)
      expect(Number.isInteger(days) && days >= 1 && days <= 365).toBe(true)
      expect(o.label.toLowerCase()).not.toContain('never')
    }
    expect(API_KEY_EXPIRY_OPTIONS.map((o) => o.value)).toContain(DEFAULT_API_KEY_EXPIRY_DAYS)
  })
})

describe('expiryOptionsFor (the organization maximum)', () => {
  it('offers nothing above the maximum and defaults to 90 days or the maximum', () => {
    const at90 = expiryOptionsFor(90)
    expect(at90.options.map((o) => o.value)).toEqual(['7', '30', '90'])
    expect(at90.defaultValue).toBe('90')

    const at45 = expiryOptionsFor(45)
    expect(at45.options.map((o) => o.value)).toEqual(['7', '30', '45'])
    expect(at45.options.at(-1)?.days).toBe(45)
    expect(at45.defaultValue).toBe('45')

    const at1 = expiryOptionsFor(1)
    expect(at1.options.map((o) => o.value)).toEqual(['1'])
    expect(at1.defaultValue).toBe('1')
  })

  it('never exceeds the platform ceiling, and falls back to it while the policy loads', () => {
    expect(expiryOptionsFor(1000).options.at(-1)?.value).toBe('365')
    expect(expiryOptionsFor(undefined).options.at(-1)?.value).toBe('365')
    expect(expiryOptionsFor(undefined).defaultValue).toBe('90')
  })
})
