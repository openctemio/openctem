import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { SensorsEmptyState } from '../sensors-empty-state'

vi.mock('next/link', () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}))

const base = {
  canPair: true,
  canInstallWithKey: true,
  canReadCI: true,
  onPair: vi.fn(),
  onInstall: vi.fn(),
}

describe('SensorsEmptyState', () => {
  it('explains what a sensor is, with pairing first and a key install second', async () => {
    const onPair = vi.fn()
    const onInstall = vi.fn()
    render(<SensorsEmptyState {...base} onPair={onPair} onInstall={onInstall} />)
    expect(screen.getByRole('heading', { name: 'Run your first sensor' })).toBeInTheDocument()
    expect(screen.getByText(/small service you run inside your network/i)).toBeInTheDocument()
    expect(screen.getByText('Scanner')).toBeInTheDocument()
    expect(screen.getByText('Collector')).toBeInTheDocument()
    const buttons = screen.getAllByRole('button')
    expect(buttons.map((b) => b.textContent)).toEqual(['Pair a sensor', 'Install with an API key'])
    await userEvent.click(buttons[0])
    expect(onPair).toHaveBeenCalled()
    await userEvent.click(buttons[1])
    expect(onInstall).toHaveBeenCalled()
  })

  it('says CI scanning needs no sensor and links to CI/CD', () => {
    render(<SensorsEmptyState {...base} />)
    expect(screen.getByText(/scanning repositories from ci needs no sensor/i)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /set up ci\/cd/i })).toHaveAttribute('href', '/ci-cd')
  })

  it('hides the CI/CD hint from a caller who may not read CI', () => {
    render(<SensorsEmptyState {...base} canReadCI={false} />)
    expect(screen.queryByRole('link', { name: /ci\/cd/i })).not.toBeInTheDocument()
  })

  it('offers only pairing where the organization allows no bearer keys', () => {
    render(<SensorsEmptyState {...base} canInstallWithKey={false} />)
    expect(screen.getByRole('button', { name: 'Pair a sensor' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /api key/i })).not.toBeInTheDocument()
  })

  it('tells a reader without either permission who can add one', () => {
    render(<SensorsEmptyState {...base} canPair={false} canInstallWithKey={false} />)
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
    expect(screen.getByText(/an organization admin can add a sensor/i)).toBeInTheDocument()
  })
})
