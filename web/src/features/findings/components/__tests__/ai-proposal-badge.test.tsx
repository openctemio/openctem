import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { AIProposalBadge } from '../ai-proposal-badge'
import { AIBadge, aiSourceOfExecutor } from '@/features/shared/components/ai-badge'

describe('AIProposalBadge', () => {
  it('marks a request proposed by AI triage, with the review hint on demand', () => {
    render(<AIProposalBadge approval={{ requested_by_actor: 'ai_triage' }} withHint />)
    expect(screen.getByText('Proposed by AI triage')).toBeInTheDocument()
    expect(screen.getByText(/not a decision/)).toBeInTheDocument()
  })

  it('names the AI application that proposed it for a person, who cannot approve it', () => {
    render(<AIProposalBadge approval={{ requested_via: 'Claude Desktop' }} withHint />)
    expect(screen.getByText('Proposed by AI application: Claude Desktop')).toBeInTheDocument()
    expect(screen.getByText(/who cannot approve it/)).toBeInTheDocument()
  })

  it('renders an application name as text, never as markup', () => {
    const { container } = render(
      <AIProposalBadge approval={{ requested_via: '<img src=x onerror=alert(1)>' }} />
    )
    expect(container.querySelector('img')).toBeNull()
  })

  it('renders nothing for a person’s request', () => {
    const { container } = render(<AIProposalBadge approval={{}} />)
    expect(container).toBeEmptyDOMElement()
  })
})

describe('AIBadge (the one shared AI label)', () => {
  it('labels each source, as a suggestion or a proposal', () => {
    const { rerender } = render(<AIBadge source="ai_builtin" />)
    expect(screen.getByTestId('ai-badge')).toHaveTextContent('Suggested by AI triage')
    rerender(<AIBadge source="ai_analyst" />)
    expect(screen.getByTestId('ai-badge')).toHaveTextContent('Suggested by AI analyst')
    rerender(<AIBadge source="ai_application" client="Desk" />)
    expect(screen.getByTestId('ai-badge')).toHaveTextContent('Suggested by AI application: Desk')
    rerender(<AIBadge source="ai_analyst" verb="proposed" />)
    expect(screen.getByTestId('ai-badge')).toHaveTextContent('Proposed by AI analyst')
  })

  it('maps run executors to sources', () => {
    expect(aiSourceOfExecutor('builtin')).toBe('ai_builtin')
    expect(aiSourceOfExecutor('platform_worker')).toBe('ai_analyst')
    expect(aiSourceOfExecutor('tenant_worker')).toBe('ai_analyst')
    expect(aiSourceOfExecutor(undefined)).toBe('ai_builtin')
  })

  it('marks an approval an AI analyst proposed', () => {
    render(<AIProposalBadge approval={{ requested_by_actor: 'ai_analyst' }} />)
    expect(screen.getByTestId('ai-badge')).toHaveAttribute('data-source', 'ai_analyst')
  })

  it('shows a control character in an application name as an escape', () => {
    render(<AIBadge source="ai_application" client={'Desk‮evil'} />)
    expect(screen.getByTestId('ai-badge').textContent).toContain('\\u{202E}')
  })
})
