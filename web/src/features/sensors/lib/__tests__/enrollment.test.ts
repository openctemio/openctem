import { describe, expect, it } from 'vitest'

import { TOKEN_SETUP_SNIPPET, parseCidrs, parseLabels, validUses } from '../enrollment'

describe('enrollment token form helpers', () => {
  it('parses key=value labels and refuses bad keys, values and too many', () => {
    expect(parseLabels('env=prod\n\nteam = blue ')).toEqual({ env: 'prod', team: 'blue' })
    expect(parseLabels('')).toEqual({})
    expect(parseLabels('Env=prod')).toBeNull()
    expect(parseLabels('novalue')).toBeNull()
    expect(parseLabels('k=\u0007')).toBeNull()
    expect(parseLabels(Array.from({ length: 21 }, (_, i) => `k${i}=v`).join('\n'))).toBeNull()
  })

  it('parses CIDRs per line or comma and refuses anything else', () => {
    expect(parseCidrs('10.20.0.0/16, 192.0.2.0/24\n2001:db8::/32')).toEqual([
      '10.20.0.0/16',
      '192.0.2.0/24',
      '2001:db8::/32',
    ])
    expect(parseCidrs('')).toEqual([])
    expect(parseCidrs('10.0.0.0')).toBeNull()
    expect(parseCidrs('300.0.0.0/8')).toBeNull()
    expect(parseCidrs('10.0.0.0/33')).toBeNull()
  })

  it('bounds the use count', () => {
    expect(validUses(1)).toBe(true)
    expect(validUses(1000)).toBe(true)
    expect(validUses(0)).toBe(false)
    expect(validUses(1001)).toBe(false)
    expect(validUses(2.5)).toBe(false)
  })

  it('never puts a token on a command line', () => {
    expect(TOKEN_SETUP_SNIPPET).not.toMatch(/octe_/)
    expect(TOKEN_SETUP_SNIPPET).toContain('umask 077')
    expect(TOKEN_SETUP_SNIPPET).toContain('SENSOR_ENROLLMENT_TOKEN_FILE')
  })
})
