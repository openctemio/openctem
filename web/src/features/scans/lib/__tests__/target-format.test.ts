import { describe, expect, it } from 'vitest'
import {
  classifyTarget,
  parsePastedTargets,
  withoutTargets,
  replaceEntryInLines,
  targetFileLines,
  targetKey,
} from '../target-format'

describe('classifyTarget', () => {
  it.each([
    ['example.com', 'domain', 'example.com'],
    ['API.Example.COM.', 'domain', 'api.example.com'],
    ['*.example.com', 'wildcard', '*.example.com'],
    ['192.0.2.10', 'ipv4', '192.0.2.10'],
    ['10.0.0.0/16', 'cidr', '10.0.0.0/16'],
    ['2001:db8::1', 'ipv6', '2001:db8::1'],
    ['2001:db8::/112', 'cidr', '2001:db8::/112'],
    ['https://app.example.com/login#top', 'url', 'https://app.example.com/login#top'],
    ['mail.example.com:587', 'host:port', 'mail.example.com:587'],
    ['[2001:DB8::1]:443', 'host:port', '[2001:db8::1]:443'],
    ['mail.example.com:25/tcp', 'host:port', 'mail.example.com:25/tcp'],
    ['bücher.de', 'domain', 'xn--bcher-kva.de'],
    ['*.Bücher.de', 'wildcard', '*.xn--bcher-kva.de'],
    ['xn--bcher-kva.de', 'domain', 'xn--bcher-kva.de'],
  ])('%s is a %s', (input, kind, value) => {
    expect(classifyTarget(input)).toMatchObject({ kind, value })
  })

  it.each([
    ['example', 'Not a domain'],
    ['*.com', 'wildcard'],
    ['300.1.1.1', 'Not a domain'],
    ['10.0.0.0/33', 'CIDR'],
    ['host.example.com:70000', 'host:port'],
    ['example.com; rm -rf /', 'characters'],
    ['$(whoami).example.com', 'characters'],
  ])('%s is invalid (%s)', (input, reason) => {
    const c = classifyTarget(input)
    expect(c.kind).toBe('invalid')
    expect(c.reason).toMatch(new RegExp(reason, 'i'))
  })

  it('decides nothing about scope: private addresses are just addresses', () => {
    expect(classifyTarget('192.168.1.10').kind).toBe('ipv4')
    expect(classifyTarget('localhost:8080').kind).toBe('host:port')
  })
})

describe('the API rules, in the browser', () => {
  it.each([
    ['10.0.0.0/8', 'larger than'],
    ['2001:db8::/32', 'larger than'],
    ['example.xn--p1ai', 'top-level domain'],
    ['[2001:db8::1]:99999', 'host:port'],
    ['[not-v6]:443', 'characters'],
  ])('%s is invalid (%s)', (input, reason) => {
    const c = classifyTarget(input)
    expect(c.kind).toBe('invalid')
    expect(c.reason).toMatch(new RegExp(reason, 'i'))
  })

  it.each([
    'git@code.example.com:team/app.git',
    'ssh://git@code.example.com/team/app',
    'https://code.example.com/team/app.git',
    'code.example.com/team/app',
    'example.com/admin',
  ])('%s is a repository or path, not a network target', (input) => {
    const c = classifyTarget(input)
    expect(c.kind).toBe('repo')
    expect(c.reasonKey).toBe('scans.targetReason.repo')
  })

  it('keeps an IDN as typed for display and sends the ASCII form', () => {
    const c = classifyTarget('Bücher.de')
    expect(c.input).toBe('Bücher.de')
    expect(c.value).toBe('xn--bcher-kva.de')
  })
})

describe('parsePastedTargets', () => {
  it('normalizes, removes repeats and counts each kind', () => {
    const p = parsePastedTargets([
      'Example.com',
      'example.com.',
      '',
      'b@d',
      '10.0.0.1',
      ' 10.0.0.1 ',
    ])
    expect(p.targets).toEqual(['example.com', '10.0.0.1'])
    expect(p.duplicates).toBe(2)
    expect(p.invalid.map((i) => i.input)).toEqual(['b@d'])
    expect(p.byKind).toEqual({ domain: 1, invalid: 1, ipv4: 1 })
  })

  it('splits on commas, semicolons and spaces', () => {
    expect(
      parsePastedTargets(['a.example.com, b.example.com;c.example.com d.example.com']).targets
    ).toEqual(['a.example.com', 'b.example.com', 'c.example.com', 'd.example.com'])
  })

  it('drops duplicates after normalisation, IDN and ASCII alike', () => {
    const p = parsePastedTargets(['bücher.de', 'XN--BCHER-KVA.DE.', 'Bücher.de'])
    expect(p.targets).toEqual(['xn--bcher-kva.de'])
    expect(p.duplicates).toBe(2)
    expect(p.duplicateInputs).toEqual(['XN--BCHER-KVA.DE.', 'Bücher.de'])
  })

  it('skips # comments, whole lines and trailing ones', () => {
    const p = parsePastedTargets([
      '# production',
      'a.example.com  # web',
      'https://b.example.com/#x',
    ])
    expect(p.targets).toEqual(['a.example.com', 'https://b.example.com/#x'])
    expect(p.invalid).toEqual([])
  })

  it('puts repositories with the entries that are not added', () => {
    const p = parsePastedTargets(['a.example.com', 'git@code.example.com:t/app.git'])
    expect(p.targets).toEqual(['a.example.com'])
    expect(p.invalid.map((i) => i.kind)).toEqual(['repo'])
    expect(p.byKind).toEqual({ domain: 1, repo: 1 })
  })

  it('handles a large list in one pass', () => {
    const lines = Array.from({ length: 5000 }, (_, i) => `h${i}.example.com`)
    const p = parsePastedTargets([...lines, ...lines])
    expect(p.targets).toHaveLength(5000)
    expect(p.duplicates).toBe(5000)
  })
})

describe('targetKey', () => {
  it('is the normalised value for a valid entry and the lower-cased input otherwise', () => {
    expect(targetKey('Example.COM.')).toBe('example.com')
    expect(targetKey('Bücher.de')).toBe('xn--bcher-kva.de')
    expect(targetKey('B@D')).toBe('b@d')
  })
})

describe('withoutTargets', () => {
  it('removes by normalised key, also inside a line holding several targets', () => {
    expect(
      withoutTargets(
        ['Example.com.', 'a.example.com, b.example.com', 'x@y'],
        ['example.com', 'b.example.com', 'x@y']
      )
    ).toEqual(['a.example.com'])
  })
})

describe('replaceEntryInLines', () => {
  it('replaces the first entry typed that way, keeping its neighbours', () => {
    expect(
      replaceEntryInLines(['a.example.com, 10.0.0.0/8', '10.0.0.0/8'], '10.0.0.0/8', '10.0.0.0/16')
    ).toEqual(['a.example.com, 10.0.0.0/16', '10.0.0.0/8'])
  })
})

describe('targetFileLines', () => {
  it('reads a CSV: drops a header row, strips quotes, keeps the columns that hold targets', () => {
    const csv = 'host,owner\n"a.example.com","web team"\nb.example.com,ops\nb@d,x\n'
    expect(targetFileLines(csv, 'targets.csv')).toEqual(['a.example.com', 'b.example.com', 'b@d'])
  })

  it('keeps the first CSV row when it holds a target', () => {
    expect(targetFileLines('a.example.com,10.0.0.1\nb.example.com,10.0.0.2', 'list.csv')).toEqual([
      'a.example.com',
      '10.0.0.1',
      'b.example.com',
      '10.0.0.2',
    ])
  })

  it('reads a text file line by line (CRLF too)', () => {
    expect(targetFileLines('a.example.com\r\nb.example.com\r\n', 'list.txt')).toEqual([
      'a.example.com',
      'b.example.com',
    ])
  })
})
