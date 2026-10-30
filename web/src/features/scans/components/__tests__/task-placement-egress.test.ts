import { describe, expect, it } from 'vitest'

import { enTranslate } from '../../lib/translate'
import { egressSensorLine } from '../task-placement'

type S = Parameters<typeof egressSensorLine>[0]

describe('egressSensorLine', () => {
  it('names the sensor and its pool for an unsupported sensor', () => {
    const s = {
      id: '1',
      name: 'edge-1',
      reasons: ['egress_unsupported'],
      egress_pool: { id: 'p', name: 'EU exit' },
    } as S
    expect(egressSensorLine(s, enTranslate)).toBe(
      'edge-1 cannot use the proxies of pool EU exit (no proxy support reported)'
    )
  })
  it('falls back to the organization proxies without a pool name', () => {
    const s = { id: '1', name: 'edge-1', reasons: ['egress_unsupported'] } as S
    expect(egressSensorLine(s, enTranslate)).toBe(
      "edge-1 cannot use the organization's proxies (no proxy support reported)"
    )
  })
  it('says a direct-only sensor host refuses the pool', () => {
    const s = { id: '1', name: 'edge-1', reasons: ['egress_host_direct'] } as S
    expect(egressSensorLine(s, enTranslate)).toBe(
      'edge-1 is set to scan direct on its host, so it takes no jobs that need a proxy'
    )
  })
  it('has its own line for validation jobs, and none for other reasons', () => {
    const v = { id: '1', name: 'edge-1', reasons: ['egress_validate_unsupported'] } as S
    expect(egressSensorLine(v, enTranslate)).toContain('no validation probes')
    expect(
      egressSensorLine({ id: '1', name: 'x', reasons: ['tool_missing'] } as S, enTranslate)
    ).toBeNull()
  })
})
