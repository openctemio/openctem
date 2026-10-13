import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ScopeTriageBadge } from '../scope-triage-badge'

const base = { attributionState: 'confirmed', confidence: 100, humanDecided: false }

describe('ScopeTriageBadge', () => {
  it('reads the gate: in scope, passive only, excluded, unknown', () => {
    const { rerender } = render(<ScopeTriageBadge triage={{ ...base, scanAllowed: true }} />)
    expect(screen.getByText('In scope')).toBeInTheDocument()
    rerender(
      <ScopeTriageBadge
        triage={{
          ...base,
          attributionState: 'discovered',
          scanAllowed: false,
          scanRefusalCode: 'no_entry',
        }}
      />
    )
    expect(screen.getByText('Not in scope · passive only')).toBeInTheDocument()
    rerender(
      <ScopeTriageBadge triage={{ ...base, scanAllowed: false, scanRefusalCode: 'no_entry' }} />
    )
    expect(screen.getByText('Not in scope')).toBeInTheDocument()
    rerender(
      <ScopeTriageBadge triage={{ ...base, scanAllowed: false, scanRefusalCode: 'excluded' }} />
    )
    expect(screen.getByText('Excluded')).toBeInTheDocument()
    rerender(<ScopeTriageBadge triage={undefined} />)
    expect(screen.getByText('-')).toBeInTheDocument()
  })
})
