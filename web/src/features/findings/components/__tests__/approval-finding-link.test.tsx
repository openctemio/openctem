import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ApprovalFindingLink } from '../approval-finding-link'

const ID = 'dcdc3001-0000-0000-0000-000000000006'

describe('ApprovalFindingLink', () => {
  it('names the finding by its title and links to it', () => {
    render(<ApprovalFindingLink findingId={ID} findingTitle="SQL injection in /login" />)
    const link = screen.getByRole('link', { name: 'SQL injection in /login' })
    expect(link).toHaveAttribute('href', `/findings/${ID}`)
  })

  it('never shows the id when the title is missing', () => {
    render(<ApprovalFindingLink findingId={ID} />)
    expect(screen.getByRole('link', { name: 'Untitled finding' })).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('dcdc3001')
  })

  it('renders a scanner title as isolated plain text', () => {
    // A right-to-left override inside a title must not reorder the text
    // around it, and control characters are stripped for display.
    render(<ApprovalFindingLink findingId={ID} findingTitle={'abc\u202Eexe.txt\u0007'} />)
    const link = screen.getByRole('link')
    expect(link).toHaveAttribute('dir', 'auto')
    expect(link.className).toContain('[unicode-bidi:isolate]')
    expect(link.textContent).not.toContain('\u0007')
  })
})
