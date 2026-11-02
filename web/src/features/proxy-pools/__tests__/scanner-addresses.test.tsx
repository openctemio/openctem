import { beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'

import { allowlistSnippet } from '../lib/allowlist'
import type { ScannerAddressList } from '../types'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

let list: ScannerAddressList | undefined
let calledWith: boolean | undefined
vi.mock('../api/use-proxy-pools', () => ({
  useScannerAddresses: (enabled: boolean) => {
    calledWith = enabled
    return { data: list, isLoading: false, error: undefined, mutate: vi.fn() }
  },
}))
const copied: string[] = []
vi.mock('@/lib/clipboard', () => ({
  copyToClipboard: async (s: string) => {
    copied.push(s)
    return true
  },
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

import {
  SCANNER_ADDRESSES_ANCHOR,
  ScannerAddressesCard,
} from '../components/scanner-addresses-card'

const sample: ScannerAddressList = {
  items: [
    {
      address: '203.0.113.9',
      cidr: '203.0.113.9/32',
      kind: 'proxy_exit',
      private: false,
      pool_name: 'egress',
      endpoint_label: 'dc1',
    },
    {
      address: '10.1.2.3',
      cidr: '10.1.2.3/32',
      kind: 'sensor',
      private: true,
      sensor_name: 'edge-1',
    },
    {
      address: '192.0.2.0/24',
      cidr: '192.0.2.0/24',
      kind: 'platform',
      private: false,
      region: 'eu',
    },
  ],
  cidrs: ['10.1.2.3/32', '192.0.2.0/24', '203.0.113.9/32'],
}

describe('allowlistSnippet', () => {
  const cidrs = ['192.0.2.0/24', '203.0.113.9/32']
  it('renders each format', () => {
    expect(allowlistSnippet(cidrs, 'lines')).toBe('192.0.2.0/24\n203.0.113.9/32')
    expect(allowlistSnippet(cidrs, 'comma')).toBe('192.0.2.0/24, 203.0.113.9/32')
    expect(allowlistSnippet(cidrs, 'allow')).toBe('allow 192.0.2.0/24;\nallow 203.0.113.9/32;')
    expect(allowlistSnippet(cidrs, 'require')).toBe('Require ip 192.0.2.0/24 203.0.113.9/32')
    expect(JSON.parse(allowlistSnippet(cidrs, 'json'))).toEqual(cidrs)
  })
  it('is empty without addresses', () => {
    expect(allowlistSnippet([], 'require')).toBe('')
  })
})

describe('ScannerAddressesCard', () => {
  beforeEach(() => {
    cleanup()
    list = sample
    calledWith = undefined
    copied.length = 0
  })

  it('lists each address with its source and offers the allowlist', async () => {
    const { container } = render(<ScannerAddressesCard />)
    expect(container.querySelector(`#${SCANNER_ADDRESSES_ANCHOR}`)).not.toBeNull()
    expect(screen.getByText('203.0.113.9')).toBeInTheDocument()
    expect(screen.getByText('Pool egress, proxy dc1')).toBeInTheDocument()
    expect(screen.getByText('Sensor edge-1, scanning without a proxy')).toBeInTheDocument()
    expect(screen.getByText('Shared sensors, region eu')).toBeInTheDocument()
    expect(screen.getAllByText('Private')).toHaveLength(1)
    expect(screen.getByTestId('scanner-addresses-snippet').textContent).toBe(
      sample.cidrs.join('\n')
    )

    fireEvent.click(screen.getByRole('button', { name: 'Copy 10.1.2.3' }))
    fireEvent.click(screen.getByTestId('scanner-addresses-copy-snippet'))
    await waitFor(() => expect(copied).toEqual(['10.1.2.3', sample.cidrs.join('\n')]))
  })

  it('explains how to learn addresses when there are none', () => {
    list = { items: [], cidrs: [] }
    render(<ScannerAddressesCard />)
    expect(screen.getByTestId('scanner-addresses-empty')).toHaveTextContent('Run a proxy test')
    expect(screen.queryByTestId('scanner-addresses-snippet')).toBeNull()
  })

  it('renders nothing and requests nothing without sensors:egress:read', () => {
    const { container } = render(<ScannerAddressesCard enabled={false} />)
    expect(container).toBeEmptyDOMElement()
    expect(calledWith).toBe(false)
  })
})
