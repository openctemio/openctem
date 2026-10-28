import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'

import { AIBadge } from '../ai-badge'

describe('AIBadge (the one shared AI label)', () => {
  it('names an AI analyst and shows the accountable owners on a muted line', () => {
    render(<AIBadge source="ai_analyst" name="Triage bot" accountable={['Jamie', 'AppSec']} />)
    expect(screen.getByTestId('ai-badge')).toHaveTextContent('AI analyst Triage bot')
    expect(screen.getByTestId('ai-badge-accountable')).toHaveTextContent(
      'Accountable: Jamie, AppSec'
    )
  })

  it('has no accountable line without owners', () => {
    render(<AIBadge source="ai_analyst" name="Triage bot" />)
    expect(screen.queryByTestId('ai-badge-accountable')).toBeNull()
  })

  it('labels each source, as a suggestion or a proposal', () => {
    const { rerender } = render(<AIBadge source="ai_builtin" />)
    expect(screen.getByTestId('ai-badge')).toHaveTextContent('Suggested by AI triage')
    rerender(<AIBadge source="ai_application" client="Desk" />)
    expect(screen.getByTestId('ai-badge')).toHaveTextContent('Suggested by AI application: Desk')
    rerender(<AIBadge source="ai_analyst" verb="proposed" />)
    expect(screen.getByTestId('ai-badge')).toHaveTextContent('Proposed by AI analyst')
    rerender(<AIBadge source="ai_analyst" verb="proposed" name="Bot" />)
    expect(screen.getByTestId('ai-badge')).toHaveTextContent('Proposed by AI analyst Bot')
  })

  it('shows a control character in an application name as an escape', () => {
    render(<AIBadge source="ai_application" client={'Desk‮evil'} />)
    expect(screen.getByTestId('ai-badge').textContent).toContain('\\u{202E}')
  })

  it('renders names as text, never as markup', () => {
    const { container } = render(
      <AIBadge source="ai_analyst" name="<img src=x onerror=alert(1)>" accountable={['<b>x</b>']} />
    )
    expect(container.querySelector('img')).toBeNull()
    expect(container.querySelector('b')).toBeNull()
  })
})
