import { describe, expect, it } from 'vitest'
import { DEFAULT_NEW_SCAN, type NewScanFormData } from '../../types'
import { durationParts, largeRangeKey, largeRangeSummary } from '../large-range'
import { formDataToCreateRequest, targetsError } from '../scan-form'
import { rangeHostBitsOf, classifyTarget } from '../target-format'

describe('largeRangeSummary', () => {
  it('counts the addresses and /16 chunks of the ranges wider than a /16', () => {
    const s = largeRangeSummary(['10.0.0.0/8', '172.16.0.0/12', '192.0.2.0/24', 'a.example.com'])
    expect(s?.ranges).toEqual(['10.0.0.0/8', '172.16.0.0/12'])
    expect(s?.addresses).toBe(BigInt(16777216 + 1048576))
    expect(s?.chunks).toBe(256 + 16)
    expect(s?.seconds).toBe(Math.ceil((16777216 + 1048576) / 1000))
    expect(largeRangeKey(s!)).toBe('10.0.0.0/8,172.16.0.0/12')
  })

  it('is null without a large range: a /16 is one target as before', () => {
    expect(largeRangeSummary(['10.0.0.0/16', '2001:db8::/112', 'a.example.com'])).toBeNull()
  })

  it('counts an IPv6 /104 as 256 /112 chunks', () => {
    expect(largeRangeSummary(['2001:db8::/104'])?.chunks).toBe(256)
  })

  it('writes a duration as hours and minutes', () => {
    expect(durationParts(16778)).toEqual({ hours: 4, minutes: 40 })
    expect(durationParts(1)).toEqual({ hours: 0, minutes: 1 })
  })
})

describe('a scan with a large range', () => {
  const form = (targets: Partial<NewScanFormData['targets']>): NewScanFormData => ({
    ...DEFAULT_NEW_SCAN,
    name: 'net',
    targets: { ...DEFAULT_NEW_SCAN.targets, ...targets },
  })

  it('is created only once its size is confirmed, and asks again when the ranges change', () => {
    expect(targetsError(form({ customTargets: ['10.0.0.0/8'] }))).toMatch(/confirm the size/i)
    expect(
      targetsError(form({ customTargets: ['10.0.0.0/8'], largeRangeConfirmed: '10.0.0.0/8' }))
    ).toBeNull()
    expect(
      targetsError(
        form({ customTargets: ['10.0.0.0/8', '172.16.0.0/12'], largeRangeConfirmed: '10.0.0.0/8' })
      )
    ).toMatch(/confirm the size/i)
  })

  it('runs live hosts first only', () => {
    expect(
      targetsError(
        form({
          customTargets: ['10.0.0.0/8'],
          largeRangeConfirmed: '10.0.0.0/8',
          targetOptions: { cidr_mode: 'sweep' },
        })
      )
    ).toMatch(/live hosts first/i)
  })

  it('leaves a /16 scan as before', () => {
    expect(targetsError(form({ customTargets: ['10.0.0.0/16'] }))).toBeNull()
  })
})

describe('the server-side confirmation', () => {
  const form = (targets: Partial<NewScanFormData['targets']>): NewScanFormData => ({
    ...DEFAULT_NEW_SCAN,
    name: 'net',
    targets: { ...DEFAULT_NEW_SCAN.targets, ...targets },
  })

  it('sends confirm_large_range only for the ranges the person confirmed', () => {
    expect(
      formDataToCreateRequest(
        form({ customTargets: ['10.0.0.0/8'], largeRangeConfirmed: '10.0.0.0/8' })
      ).confirm_large_range
    ).toBe(true)
    expect(
      formDataToCreateRequest(form({ customTargets: ['10.0.0.0/8'] })).confirm_large_range
    ).toBeUndefined()
    expect(
      formDataToCreateRequest(
        form({ customTargets: ['10.0.0.0/8', '172.16.0.0/12'], largeRangeConfirmed: '10.0.0.0/8' })
      ).confirm_large_range
    ).toBeUndefined()
    expect(
      formDataToCreateRequest(form({ customTargets: ['10.0.0.0/16'] })).confirm_large_range
    ).toBeUndefined()
  })
})

describe("the organization's widest range", () => {
  it('is a /16 unless the organization opted in to a wider one', () => {
    expect(rangeHostBitsOf(undefined)).toBe(16)
    expect(rangeHostBitsOf(0)).toBe(16)
    expect(rangeHostBitsOf(8)).toBe(24)
    expect(rangeHostBitsOf(20)).toBe(12)
  })

  it('refuses a /8 at the default and takes it once opted in', () => {
    expect(classifyTarget('10.0.0.0/8', { maxHostBits: rangeHostBitsOf(undefined) }).kind).toBe(
      'invalid'
    )
    expect(classifyTarget('10.0.0.0/8', { maxHostBits: rangeHostBitsOf(8) }).kind).toBe('cidr')
  })
})
