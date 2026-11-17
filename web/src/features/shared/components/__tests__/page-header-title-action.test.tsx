import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { PageHeader } from '../page-header'

describe('PageHeader title action', () => {
  it('draws the control on the title line, after the title and outside the h1', () => {
    render(
      <PageHeader title="Overview" titleAction={<button aria-label="Switch dashboard" />}>
        <button>Edit</button>
      </PageHeader>
    )
    const h1 = screen.getByRole('heading', { level: 1, name: 'Overview' })
    const action = screen.getByRole('button', { name: 'Switch dashboard' })
    expect(h1).not.toContainElement(action)
    const line = document.querySelector('[data-slot="page-header-title-line"]') as HTMLElement
    expect(line).toContainElement(h1)
    expect(line).toContainElement(action)
    expect(line).not.toContainElement(screen.getByText('Edit'))
    expect(h1.compareDocumentPosition(action) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })

  it('keeps the plain h1 without one', () => {
    render(<PageHeader title="Assets" />)
    expect(document.querySelector('[data-slot="page-header-title-line"]')).toBeNull()
    expect(screen.getByRole('heading', { level: 1, name: 'Assets' })).toHaveAttribute(
      'id',
      'page-title'
    )
  })
})
