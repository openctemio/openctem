import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { AIProposalBadge } from '../ai-proposal-badge'

describe('AIProposalBadge', () => {
  it('marks a request proposed by AI triage, with the review hint on demand', () => {
    render(<AIProposalBadge approval={{ requested_by_actor: 'ai_triage' }} withHint />)
    expect(screen.getByText('Proposed by AI triage')).toBeInTheDocument()
    expect(screen.getByText(/not a decision/)).toBeInTheDocument()
  })

  it('renders nothing for a person’s request', () => {
    const { container } = render(<AIProposalBadge approval={{}} />)
    expect(container).toBeEmptyDOMElement()
  })
})
