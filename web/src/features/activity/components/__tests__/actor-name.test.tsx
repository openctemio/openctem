import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'

import { ActorName } from '../activity-items'

describe('ActorName', () => {
  it('renders an AI analyst as the shared AI badge with its accountable owners', () => {
    render(
      <ActorName
        actor={{
          name: 'Triage bot',
          kind: 'ai',
          ai: { name: 'Triage bot', accountable: ['Jamie', 'AppSec'] },
        }}
      />
    )
    expect(screen.getByTestId('ai-badge')).toHaveTextContent('AI analyst Triage bot')
    expect(screen.getByTestId('ai-badge-accountable')).toHaveTextContent(
      'Accountable: Jamie, AppSec'
    )
  })

  it('reads AI assistant for an AI row without provenance, and a person by name', () => {
    const { rerender } = render(<ActorName actor={{ name: 'AI assistant', kind: 'ai' }} />)
    expect(screen.getByText('AI assistant')).toBeInTheDocument()
    rerender(<ActorName actor={{ name: 'Jamie', kind: 'user' }} />)
    expect(screen.getByText('Jamie')).toBeInTheDocument()
  })
})
