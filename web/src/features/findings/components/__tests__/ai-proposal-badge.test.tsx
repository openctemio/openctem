import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { AIProposalBadge } from '../ai-proposal-badge'

describe('AIProposalBadge', () => {
  it('marks a request proposed by AI triage, with the review hint on demand', () => {
    render(<AIProposalBadge approval={{ requested_by_actor: 'ai_triage' }} withHint />)
    expect(screen.getByText('Proposed by AI triage')).toBeInTheDocument()
    expect(screen.getByText(/not a decision/)).toBeInTheDocument()
  })

  it('names the AI application that proposed it for a person, who cannot approve it', () => {
    render(<AIProposalBadge approval={{ requested_via: 'Claude Desktop' }} withHint />)
    expect(screen.getByText('Proposed by AI agent: Claude Desktop')).toBeInTheDocument()
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
