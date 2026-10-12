import { describe, expect, it } from 'vitest'
import { buildCvssVector, cvssVersionOf, parseCvssVector, scoreCvss } from '../cvss'

describe('cvss', () => {
  it('scores 3.1 vectors per the specification', () => {
    const p = parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')!
    expect(p.complete).toBe(true)
    expect(scoreCvss('3.1', p.metrics)).toBe(9.8)
    const scoped = parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N')!
    expect(scoreCvss('3.1', scoped.metrics)).toBe(5.4)
  })

  it('scores 4.0 vectors with the macro-vector table', () => {
    const p = parseCvssVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')!
    expect(scoreCvss('4.0', p.metrics)).toBe(9.3)
    const low = parseCvssVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N')!
    expect(scoreCvss('4.0', low.metrics)).toBe(5.3)
  })

  it('does not score a partial vector', () => {
    const p = parseCvssVector('CVSS:3.1/AV:N/AC:L')!
    expect(p.complete).toBe(false)
    expect(scoreCvss('3.1', p.metrics)).toBeNull()
  })

  it('refuses unknown versions, invalid values and repeated metrics', () => {
    expect(parseCvssVector('CVSS:2.0/AV:N')).toBeNull()
    expect(parseCvssVector('AV:N/AC:L')).toBeNull()
    expect(parseCvssVector('CVSS:3.1/AV:X')).toBeNull()
    expect(parseCvssVector('CVSS:3.1/AV:N/AV:L')).toBeNull()
    expect(parseCvssVector('CVSS:3.1/AV:N:L')).toBeNull()
  })

  it('ignores non-base metrics and normalises case', () => {
    const p = parseCvssVector('cvss:3.1/av:n/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O')!
    expect(p.complete).toBe(true)
    expect(buildCvssVector('3.1', p.metrics)).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
  })

  it('reads the version from the prefix', () => {
    expect(cvssVersionOf('CVSS:4.0/AV:N')).toBe('4.0')
    expect(cvssVersionOf('CVSS:3.1/')).toBe('3.1')
    expect(cvssVersionOf('nope')).toBeNull()
  })
})
