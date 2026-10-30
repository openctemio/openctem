import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ScopeTriageBadge } from '../scope-triage-badge'

const base = { attributionState: 'confirmed', confidence: 100, humanDecided: false }

const chip = () => document.querySelector('[data-slot="tone-chip"]') as HTMLElement

describe('ScopeTriageBadge', () => {
  it('reads the gate in the attention tones: in scope, not in scope, excluded, unknown', () => {
    const { rerender } = render(<ScopeTriageBadge triage={{ ...base, scanAllowed: true }} />)
    expect(screen.getByText('In scope')).toBeInTheDocument()
    expect(chip().dataset.tone).toBe('ok')
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
    // One short word; passive-only is said in the tooltip, with no separator glyph.
    expect(screen.getByText('Not in scope')).toBeInTheDocument()
    expect(chip().dataset.tone).toBe('caution')
    expect(chip().title).toMatch(/passive checks only/)
    expect(chip().textContent).not.toMatch(/·/)
    rerender(
      <ScopeTriageBadge triage={{ ...base, scanAllowed: false, scanRefusalCode: 'excluded' }} />
    )
    expect(screen.getByText('Excluded')).toBeInTheDocument()
    expect(chip().dataset.tone).toBe('neutral')
    rerender(<ScopeTriageBadge triage={undefined} />)
    expect(screen.getByText('-')).toBeInTheDocument()
  })

  it('shortens the guardrail hold and keeps its full reason in the tooltip', () => {
    render(
      <ScopeTriageBadge triage={{ ...base, scanAllowed: false, scanRefusalCode: 'guardrailed' }} />
    )
    expect(screen.getByText('Guardrail hold')).toBeInTheDocument()
    expect(chip().title).toMatch(/^Held by a platform guardrail: /)
    expect(chip().dataset.tone).toBe('caution')
  })

  it('marks a deny-list refusal as danger', () => {
    render(
      <ScopeTriageBadge triage={{ ...base, scanAllowed: false, scanRefusalCode: 'deny_list' }} />
    )
    expect(chip().dataset.tone).toBe('danger')
  })
})
