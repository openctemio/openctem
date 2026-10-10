import { describe, expect, it } from 'vitest'
import { itemLimit, portLimit } from '../program-targets'

describe('program target limits', () => {
  it('formats a port limit', () => {
    expect(portLimit('8443', 'tcp')).toBe('8443/tcp')
    expect(portLimit('80,443')).toBe('80,443')
    expect(portLimit(undefined, 'udp')).toBe('udp')
    expect(portLimit()).toBe('')
  })

  it('names the path of a path-limited URL target', () => {
    expect(
      itemLimit({
        raw: 'https://x.example/api/',
        in_scope: true,
        kind: 'url',
        pattern: 'https://x.example/api*',
      })
    ).toBe('/api')
    expect(
      itemLimit({ raw: 'x.example', in_scope: true, kind: 'domain', pattern: 'x.example' })
    ).toBe('')
    expect(
      itemLimit({
        raw: 'x.example:8443',
        in_scope: true,
        kind: 'domain',
        pattern: 'x.example',
        ports: '8443',
        protocol: 'tcp',
      })
    ).toBe('8443/tcp')
  })
})
