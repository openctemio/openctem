import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'

import { RetiredBadge, RetiredNotice } from '../retired-workflow'

const replacement = { id: 'r1', name: 'Subdomains' }

describe('RetiredBadge', () => {
  it('says Retired and, on hover, what replaced the workflow', () => {
    render(<RetiredBadge workflow={{ is_retired: true, superseded_by: replacement }} />)
    const badge = screen.getByText('Retired')
    expect(badge).toHaveAttribute('title', 'Retired, replaced by Subdomains')
  })

  it('says there is no direct replacement when none is set', () => {
    render(<RetiredBadge workflow={{ is_retired: true }} />)
    expect(screen.getByText('Retired')).toHaveAttribute('title', 'Retired, no direct replacement')
  })
})

describe('RetiredNotice', () => {
  it('links the replacement of a retired system workflow', () => {
    render(<RetiredNotice workflow={{ is_retired: true, superseded_by: replacement }} />)
    expect(screen.getByText('This workflow is retired')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open Subdomains' })).toHaveAttribute(
      'href',
      '/scans/workflows/r1'
    )
  })

  it('tells a copy it is based on a retired template and links the replacement', () => {
    render(
      <RetiredNotice
        workflow={{
          based_on_retired: { id: 's1', name: 'Discover', superseded_by: replacement },
        }}
      />
    )
    expect(screen.getByText('Based on a retired template')).toBeInTheDocument()
    expect(
      screen.getByText(/made from Discover, which is retired and replaced by Subdomains/)
    ).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open Subdomains' })).toBeInTheDocument()
  })

  it('renders nothing for an ordinary workflow', () => {
    const { container } = render(<RetiredNotice workflow={{}} />)
    expect(container).toBeEmptyDOMElement()
  })
})
