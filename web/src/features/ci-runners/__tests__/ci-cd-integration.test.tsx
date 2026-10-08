import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CICDIntegration, cicdTab } from '../components/ci-cd-integration'
import { CICDLinkCard } from '../components/ci-cd-link-card'
import { DOCS } from '@/lib/docs-links'

vi.mock('../components/ci-pipelines-panel', () => ({
  CIPipelinesPanel: () => <div data-testid="pipelines-panel" />,
}))
vi.mock('../components/ci-trust-settings', () => ({
  CITrustSettings: ({ embedded }: { embedded?: boolean }) => (
    <div data-testid="trust-settings" data-embedded={String(!!embedded)} />
  ),
}))
vi.mock('next/link', () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}))

describe('CI/CD integration page', () => {
  beforeEach(() => {
    window.history.replaceState(null, '', '/ci-cd')
  })

  it('opens on the pipelines, with the provider guides', () => {
    render(<CICDIntegration />)
    expect(screen.getByRole('heading', { name: 'CI/CD integration' })).toBeInTheDocument()
    expect(screen.getByTestId('pipelines-panel')).toBeInTheDocument()
    expect(screen.queryByTestId('trust-settings')).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: /github actions guide/i })).toHaveAttribute(
      'href',
      DOCS.ci.githubActions
    )
    expect(screen.getByRole('link', { name: /gitlab ci guide/i })).toHaveAttribute(
      'href',
      DOCS.ci.gitlabCi
    )
  })

  it('shows trust, gate policy and break-glass under Trust and gate, without a second header', async () => {
    render(<CICDIntegration />)
    await userEvent.click(screen.getByRole('tab', { name: /trust and gate/i }))
    expect(screen.getByTestId('trust-settings')).toHaveAttribute('data-embedded', 'true')
    expect(screen.queryByTestId('pipelines-panel')).not.toBeInTheDocument()
  })

  it('reads the tab from the URL', () => {
    expect(cicdTab('setup')).toBe('setup')
    expect(cicdTab('')).toBe('pipelines')
    expect(cicdTab('anything')).toBe('pipelines')
  })
})

describe('CICDLinkCard', () => {
  it('links to CI/CD integration with the pipeline count', () => {
    render(<CICDLinkCard count={3} />)
    const link = screen.getByRole('link', { name: /ci\/cd pipelines \(3\)/i })
    expect(link).toHaveAttribute('href', '/ci-cd')
  })
})
