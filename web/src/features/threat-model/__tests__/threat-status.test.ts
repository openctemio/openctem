import { describe, expect, it } from 'vitest'
import { THREAT_STATUS_STYLES, THREAT_STATUS_ORDER } from '../lib/threat-status'

describe('threat status tone map', () => {
  it('maps every status to its workflow tone and label key', () => {
    expect(
      Object.fromEntries(Object.entries(THREAT_STATUS_STYLES).map(([k, v]) => [k, v.tone]))
    ).toEqual({
      open: 'open',
      mitigated: 'resolved',
      covered: 'resolved',
      accepted: 'accepted',
      theoretical: 'triage',
    })
    for (const s of THREAT_STATUS_ORDER) {
      expect(THREAT_STATUS_STYLES[s].labelKey).toBe(`threatModel.status.${s}`)
    }
  })
})
