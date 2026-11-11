import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { NamesCell, NetworkCell, PortsCell } from '../ip-cells'
import type { Asset } from '../../../types/asset.types'

const ip: NonNullable<Asset['ip']> = {
  network: '198.51.100.0/24',
  names: ['a.example.com', 'b.example.com', 'c.example.com'],
  namesTotal: 7,
  ports: [
    { port: 22, transport: 'tcp', service: 'ssh' },
    { port: 80, transport: 'tcp', service: 'http' },
    { port: 443, transport: 'tcp', service: 'https' },
    { port: 53, transport: 'udp' },
    { port: 8080 },
  ],
  portsTotal: 9,
}

describe('IP addresses tab cells', () => {
  it('the network is a button that filters to it', () => {
    const onFilter = vi.fn()
    render(<NetworkCell ip={ip} onFilter={onFilter} />)
    fireEvent.click(screen.getByTestId('ip-network-cell'))
    expect(onFilter).toHaveBeenCalledWith('198.51.100.0/24')
  })

  it('shows up to three names and the rest as +N', () => {
    render(<NamesCell ip={ip} />)
    const cell = screen.getByTestId('ip-names-cell')
    expect(cell).toHaveTextContent('a.example.com')
    expect(cell).toHaveTextContent('c.example.com')
    expect(cell).toHaveTextContent('+4')
  })

  it('shows up to five ports as 443/tcp https and the rest as +N', () => {
    render(<PortsCell ip={ip} />)
    const cell = screen.getByTestId('ip-ports-cell')
    expect(cell).toHaveTextContent('443/tcp https')
    expect(cell).toHaveTextContent('53/udp')
    expect(cell).toHaveTextContent('+4')
  })

  it('draws scan output as text, never as markup', () => {
    render(
      <NamesCell
        ip={{
          ...ip,
          names: ['<img src=x onerror=alert(1)>'],
          namesTotal: 1,
          ports: [],
          portsTotal: 0,
        }}
      />
    )
    const cell = screen.getByTestId('ip-names-cell')
    expect(cell.querySelector('img')).toBeNull()
    expect(cell.textContent).toContain('<img')
  })

  it('shows a dash when nothing is known', () => {
    render(<PortsCell ip={undefined} />)
    expect(screen.getByText('—')).toBeInTheDocument()
  })
})
