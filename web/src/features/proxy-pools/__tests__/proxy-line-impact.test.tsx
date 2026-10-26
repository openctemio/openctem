import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

import { defaultPoolImpacts } from '../lib/impact'
import { buildProxyLine, clearCredentialLines, isPrivateProxyHost } from '../lib/proxy-line'
import { ImpactList } from '../components/impact-list'
import { PasteListField } from '../components/paste-list-field'

vi.mock('@/components/link', () => ({
  default: ({ href, children }: { href: string; children: React.ReactNode }) => (
    <a href={href}>{children}</a>
  ),
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver
Element.prototype.hasPointerCapture ??= () => false
Element.prototype.releasePointerCapture ??= () => {}
Element.prototype.scrollIntoView ??= () => {}

const full = ['egress.upstream@1', 'net.confined@1', 'egress.validate@1']
const sensor = (id: string, name: string, caps: string[] | null, status = 'active') =>
  ({
    id,
    name,
    status,
    type: 'sensor',
    execution_mode: 'daemon',
    reported: caps === null ? null : { capabilities: caps },
  }) as unknown as Parameters<typeof defaultPoolImpacts>[0][number]

describe('defaultPoolImpacts', () => {
  const pools = [{ id: 'd', enabled: false, is_default: true }]
  it('groups the sensors the default pool would hold back, by reason', () => {
    const impacts = defaultPoolImpacts(
      [
        sensor('1', 'old', []),
        sensor('2', 'half', ['egress.upstream@1', 'net.confined@1']),
        sensor('3', 'ready', full),
        sensor('4', 'own-path', []),
        sensor('5', 'off', [], 'disabled'),
        sensor('6', 'never-reported', null),
      ],
      [{ sensor_id: '4', mode: 'direct' }],
      pools
    )
    expect(impacts.map((i) => [i.name, i.warning])).toEqual([
      ['half', 'validate-waits'],
      ['never-reported', 'unsupported'],
      ['old', 'unsupported'],
    ])
  })
  it('works when the organization has no default pool yet', () => {
    expect(defaultPoolImpacts([sensor('1', 'old', [])], [], [])).toHaveLength(1)
  })
  it('a sensor on a pool of its own is not an impact of the default pool', () => {
    expect(
      defaultPoolImpacts(
        [sensor('1', 'old', [])],
        [{ sensor_id: '1', mode: 'pool', pool_id: 'x' }],
        pools
      )
    ).toHaveLength(0)
  })
})

describe('ImpactList', () => {
  it('renders nothing without impacts and links each sensor otherwise', () => {
    const { container, rerender } = render(<ImpactList impacts={[]} pending />)
    expect(container).toBeEmptyDOMElement()
    rerender(
      <ImpactList
        pending
        impacts={[
          { id: '1', name: 'old', warning: 'unsupported' },
          { id: '2', name: 'half', warning: 'validate-waits' },
        ]}
      />
    )
    expect(screen.getByTestId('proxy-impact-unsupported')).toHaveTextContent('old')
    expect(screen.getByTestId('proxy-impact-validate-waits')).toHaveTextContent('half')
    expect(screen.getByRole('link', { name: 'old' })).toHaveAttribute('href', '/sensors')
  })
})

describe('buildProxyLine', () => {
  const base = { scheme: 'socks5', host: 'proxy.example.com', port: '1080', label: '' } as const
  it('encodes @ : # / % and space in the credentials', () => {
    const r = buildProxyLine({ ...base, username: 'a@b', password: 'p:w#d/%x y' })
    expect(r).toEqual({ line: 'socks5://a%40b:p%3Aw%23d%2F%25x%20y@proxy.example.com:1080' })
  })
  it('round-trips through URL parsing', () => {
    const r = buildProxyLine({ ...base, username: 'u@h', password: '@:#/' })
    if (!('line' in r)) throw new Error('no line')
    const u = new URL(r.line)
    expect(decodeURIComponent(u.username)).toBe('u@h')
    expect(decodeURIComponent(u.password)).toBe('@:#/')
    expect(u.host).toBe('proxy.example.com:1080')
  })
  it('brackets IPv6, adds the label, and refuses bad fields', () => {
    expect(
      buildProxyLine({ ...base, host: '2001:db8::1', username: '', password: '', label: 'eu' })
    ).toEqual({
      line: 'socks5://[2001:db8::1]:1080#eu',
    })
    expect(buildProxyLine({ ...base, host: 'a b', username: '', password: '' })).toEqual({
      problem: 'host',
    })
    expect(buildProxyLine({ ...base, port: '70000', username: '', password: '' })).toEqual({
      problem: 'port',
    })
    expect(buildProxyLine({ ...base, username: '', password: 'x' })).toEqual({ problem: 'user' })
    expect(buildProxyLine({ ...base, username: '', password: '', label: 'a:b' })).toEqual({
      problem: 'label',
    })
  })
})

describe('clearCredentialLines', () => {
  it('flags socks5 and http credentials on a public address only', () => {
    const text = [
      'socks5://u:p@203.0.113.9:1080',
      'socks5://u:p@10.0.0.5:1080',
      'http://u:p@proxy.example.com:3128#eu',
      'https://u:p@proxy.example.com:443',
      'socks5://203.0.113.9:1080',
      'socks5://••••@198.51.100.1:1080',
      '# socks5://u:p@203.0.113.50:1',
      'socks5://u:p@gw.corp:1080',
      'socks5h://u:p@[2001:db8::1]:1080',
    ].join('\n')
    expect(clearCredentialLines(text).map((c) => [c.line, c.scheme, c.host])).toEqual([
      [1, 'socks5', '203.0.113.9'],
      [3, 'http', 'proxy.example.com'],
      [6, 'socks5', '198.51.100.1'],
      [9, 'socks5h', '[2001:db8::1]'],
    ])
  })
  it('knows private ranges', () => {
    for (const h of [
      '10.1.1.1',
      '172.16.0.1',
      '172.31.9.9',
      '192.168.1.1',
      '100.64.0.1',
      'fd00::1',
      'proxy',
      'a.internal',
    ])
      expect(isPrivateProxyHost(h), h).toBe(true)
    for (const h of ['172.32.0.1', '8.8.8.8', 'proxy.example.com', '2001:db8::1'])
      expect(isPrivateProxyHost(h), h).toBe(false)
  })
})

describe('PasteListField', () => {
  it('warns for socks5 credentials on a public address, not a private one', () => {
    const { rerender } = render(
      <PasteListField value="socks5://u:p@203.0.113.9:1080" onChange={() => {}} />
    )
    expect(screen.getByTestId('proxy-clear-credentials')).toHaveTextContent('203.0.113.9')
    rerender(<PasteListField value="socks5://u:p@10.0.0.9:1080" onChange={() => {}} />)
    expect(screen.queryByTestId('proxy-clear-credentials')).toBeNull()
  })
  it('adds a built line with the password encoded', () => {
    const onChange = vi.fn()
    render(<PasteListField value="" onChange={onChange} />)
    fireEvent.click(screen.getByText('Build a line'))
    fireEvent.change(screen.getByLabelText('Host'), { target: { value: 'p.example.com' } })
    fireEvent.change(screen.getByLabelText('Port'), { target: { value: '3128' } })
    fireEvent.change(screen.getByLabelText('User name (optional)'), { target: { value: 'me' } })
    fireEvent.change(screen.getByLabelText('Password (optional)'), { target: { value: 'a@b:c' } })
    fireEvent.click(screen.getByText('Add line'))
    expect(onChange).toHaveBeenCalledWith('https://me:a%40b%3Ac@p.example.com:3128')
  })
})
