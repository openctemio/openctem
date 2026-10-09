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
})
