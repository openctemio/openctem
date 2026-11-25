/**
 * A value that is not the row's name wraps to two lines at most; past that it
 * ends in an ellipsis with its full text reachable (the layout matrix's
 * cutMeaning rule).
 */
import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { CellText } from '../cell-text'
import { StackedCell } from '../stacked-cell'
import { RowNameLink } from '../row-name-link'

describe('CellText', () => {
  it('wraps to two lines and carries its full text as the title', () => {
    render(<CellText>Static Application Security Testing - analyze source code</CellText>)
    const el = document.querySelector('[data-slot="cell-text"]')!
    expect(el).toHaveClass('line-clamp-2', 'whitespace-normal', 'break-words')
    expect(el).not.toHaveClass('truncate')
    expect(el).toHaveAttribute('data-cut-tooltip', '')
    expect(el).toHaveAttribute('title', 'Static Application Security Testing - analyze source code')
  })

  it('wraps an e-mail at its separators and keeps the text unchanged', () => {
    render(<CellText>e2e-owner@openctem-test.local</CellText>)
    const el = document.querySelector('[data-slot="cell-text"]')!
    expect(el.textContent).toBe('e2e-owner@openctem-test.local')
    expect(el.querySelectorAll('wbr').length).toBeGreaterThan(0)
  })

  it('takes the full text from title when the value is not plain text', () => {
    render(
      <CellText title="Rejected by Unknown person">
        <span>Rejected by Unknown person</span>
      </CellText>
    )
    expect(document.querySelector('[data-slot="cell-text"]')).toHaveAttribute(
      'title',
      'Rejected by Unknown person'
    )
  })
})

describe('StackedCell truncate', () => {
  it('holds a plain-text line to two lines with its full text as the title', () => {
    render(
      <StackedCell
        truncate
        primary="Example Trust Services Issuing CA 2 (Extended Validation)"
        secondary="Example Trust Services"
      />
    )
    const top = screen.getByText('Example Trust Services Issuing CA 2 (Extended Validation)')
    expect(top).toHaveClass('line-clamp-2')
    expect(top).not.toHaveClass('line-clamp-1')
    expect(top).toHaveAttribute('data-cut-tooltip', '')
    expect(top).toHaveAttribute(
      'title',
      'Example Trust Services Issuing CA 2 (Extended Validation)'
    )
  })

  it('does not mark a line that is not plain text (no title to hold it)', () => {
    render(<StackedCell truncate primary={<b>node</b>} />)
    const top = screen.getByText('node').parentElement!
    expect(top).not.toHaveAttribute('data-cut-tooltip')
  })
})

describe('RowNameLink', () => {
  it('uses its plain-text name as the title when none is given', () => {
    render(
      <RowNameLink href="/components/c-1" onOpen={() => {}}>
        Payments platform external perimeter
      </RowNameLink>
    )
    const link = screen.getByRole('link')
    expect(link).toHaveAttribute('title', 'Payments platform external perimeter')
    expect(link).toHaveAttribute('data-cut-tooltip', '')
  })
})
