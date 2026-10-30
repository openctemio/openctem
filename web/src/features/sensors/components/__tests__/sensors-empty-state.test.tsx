import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { SensorsEmptyState } from '../sensors-empty-state'

vi.mock('../sensor-onboarding-panel', () => ({
  SensorOnboardingPanel: ({
    canInstallWithKey,
    onInstallWithKey,
  }: {
    canInstallWithKey?: boolean
    onInstallWithKey?: () => void
  }) => (
    <div data-testid="onboarding-panel">
      {canInstallWithKey && (
        <button type="button" onClick={onInstallWithKey}>
          key
        </button>
      )}
    </div>
  ),
}))

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
  onInstall: vi.fn(),
}

describe('SensorsEmptyState', () => {
  it('explains what a sensor is and shows the Add sensor panel inline', async () => {
    const onInstall = vi.fn()
    render(<SensorsEmptyState {...base} onInstall={onInstall} />)
    expect(screen.getByRole('heading', { name: 'Run your first sensor' })).toBeInTheDocument()
    expect(screen.getByText(/small service you run inside your network/i)).toBeInTheDocument()
    expect(screen.getByText('Scanner')).toBeInTheDocument()
    expect(screen.getByText('Collector')).toBeInTheDocument()
    expect(screen.getByTestId('onboarding-panel')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'key' }))
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

  it('offers the key install alone to a caller who may not pair', async () => {
    const onInstall = vi.fn()
    render(<SensorsEmptyState {...base} canPair={false} onInstall={onInstall} />)
    expect(screen.queryByTestId('onboarding-panel')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Install with an API key' }))
    expect(onInstall).toHaveBeenCalled()
  })

  it('tells a reader without either permission who can add one', () => {
    render(<SensorsEmptyState {...base} canPair={false} canInstallWithKey={false} />)
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
    expect(screen.getByText(/an organization admin can add a sensor/i)).toBeInTheDocument()
  })
})
