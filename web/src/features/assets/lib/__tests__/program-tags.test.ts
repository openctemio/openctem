import { describe, expect, it } from 'vitest'
import { programTargetInfo } from '../program-tags'

describe('programTargetInfo', () => {
  it('reads the program system tags', () => {
    expect(
      programTargetInfo([
        'bug-bounty',
        'platform:hackerone',
        'program-unattested',
        'program:hackerone:acme',
        'source:programfeed',
      ])
    ).toEqual({ programs: ['hackerone/acme'], platforms: ['hackerone'], unattested: true })
  })

  it('is null for an asset without program links', () => {
    expect(programTargetInfo(undefined)).toBeNull()
    expect(programTargetInfo(['platform:aws'])).toBeNull()
  })
})
