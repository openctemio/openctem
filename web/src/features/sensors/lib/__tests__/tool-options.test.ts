import { describe, expect, it } from 'vitest'

import { boundsText, toolOptions } from '../tool-options'

const descriptor = {
  name: 'nuclei',
  config: {
    type: 'object',
    properties: {
      severity: {
        type: 'array',
        items: { type: 'string', enum: ['low', 'high'] },
        default: ['high'],
        'x-octm-scope': 'scan',
        'x-octm-flag': '-severity',
        'x-octm-group': 'Templates',
        'x-octm-order': 20,
      },
      retries: { type: 'integer', minimum: 0, maximum: 5, 'x-octm-common': 'retries' },
      rate_limit: {
        type: 'integer',
        minimum: 1,
        maximum: 5000,
        default: 150,
        title: 'Rate',
        'x-octm-common': 'rate',
        'x-octm-flag': '-rate-limit',
        'x-octm-scope': 'scan',
      },
      code: {
        type: 'boolean',
        'x-octm-tier': 'T2',
        'x-octm-group': 'Templates',
        'x-octm-order': 10,
      },
      net: {
        type: 'object',
        title: 'Network',
        properties: { probe_ms: { type: 'integer', 'x-octm-tier': 'T1' } },
      },
    },
  },
}

describe('toolOptions', () => {
  it('puts common options first, then groups by order', () => {
    const keys = toolOptions(descriptor).map((o) => o.key)
    expect(keys).toEqual(['rate_limit', 'retries', 'net.probe_ms', 'code', 'severity'])
  })

  it('reads types, bounds, defaults, scope, safety and flags', () => {
    const [rate, retries, probe, code, severity] = toolOptions(descriptor)
    expect(rate).toMatchObject({
      common: 'rate',
      flag: '-rate-limit',
      defaultValue: '150',
      scope: 'scan',
      safety: 'safe',
    })
    expect(boundsText(rate)).toBe('1–5000')
    expect(retries.scope).toBe('sensor')
    expect(probe).toMatchObject({ group: 'Network', safety: 'impact' })
    expect(code.safety).toBe('dangerous')
    expect(severity).toMatchObject({ values: ['low', 'high'], defaultValue: 'high' })
  })

  it('returns nothing for a descriptor without a schema', () => {
    expect(toolOptions(undefined)).toEqual([])
    expect(toolOptions({ name: 'x' })).toEqual([])
    expect(toolOptions({ config: { properties: 'x' } })).toEqual([])
  })

  it('treats the descriptor as untrusted', () => {
    const hostile = {
      config: {
        properties: {
          a: {
            type: 'function',
            'x-octm-common': 'proxy',
            'x-octm-flag': '-c 5; rm',
            title: 'x'.repeat(2000),
          },
          b: 'not an object',
          c: { type: 'integer', minimum: 'NaN', default: { nested: true }, 'x-octm-tier': 'T9' },
          ...Object.fromEntries(
            Array.from({ length: 100 }, (_, i) => [`k${i}`, { type: 'string' }])
          ),
        },
      },
    }
    const opts = toolOptions(hostile)
    expect(opts.length).toBeLessThanOrEqual(64)
    const a = opts.find((o) => o.key === 'a')!
    expect(a.type).toBe('')
    expect(a.common).toBeUndefined()
    expect(a.flag).toBeUndefined()
    expect(a.title!.length).toBeLessThanOrEqual(501)
    expect(opts.find((o) => o.key === 'b')).toBeUndefined()
    const c = opts.find((o) => o.key === 'c')!
    expect(c.minimum).toBeUndefined()
    expect(c.defaultValue).toBeUndefined()
    expect(c.safety).toBe('safe')
  })

  it('formats one-sided bounds', () => {
    expect(boundsText({ minimum: 0 } as never)).toBe('≥ 0')
    expect(boundsText({ maximum: 9 } as never)).toBe('≤ 9')
    expect(boundsText({} as never)).toBe('')
  })
})
