import { describe, expect, it } from 'vitest'
import { readPosture } from '../lib/origin-posture'

describe('readPosture', () => {
  it('is null when the property is absent or unusable', () => {
    expect(readPosture(undefined)).toBeNull()
    expect(readPosture({})).toBeNull()
    expect(readPosture({ http_posture: 'x' })).toBeNull()
    expect(readPosture({ http_posture: [] })).toBeNull()
    expect(readPosture({ http_posture: {} })).toBeNull()
  })

  it('marks present and missing headers, by list or by map', () => {
    const byList = readPosture({
      http_posture: { headers: ['Strict-Transport-Security', 'x-frame-options'] },
    })
    expect(byList?.headers.filter((h) => h.present).map((h) => h.key)).toEqual([
      'strict_transport_security',
      'x_frame_options',
    ])
    const byMap = readPosture({
      http_posture: { headers: { csp: true, hsts: false, referrer_policy: 'x' } },
    })
    expect(byMap?.headers.filter((h) => h.present).map((h) => h.key)).toEqual([
      'content_security_policy',
      'referrer_policy',
    ])
  })

  it('reads cookie flags and skips malformed cookies', () => {
    const p = readPosture({
      http_posture: {
        cookies: [
          { name: 'sid', secure: true, http_only: false, same_site: 'Lax' },
          { secure: true },
          'bad',
        ],
      },
    })
    expect(p?.cookies).toEqual([{ name: 'sid', secure: true, httpOnly: false, sameSite: 'Lax' }])
  })
})
