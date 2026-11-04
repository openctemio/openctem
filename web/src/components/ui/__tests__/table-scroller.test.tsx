import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Table, TableBody, TableCell, TableRow } from '../table'

describe('Table scroller', () => {
  it('is a named region in the tab order, so a wide table scrolls by keyboard', () => {
    const { container } = render(
      <Table>
        <TableBody>
          <TableRow>
            <TableCell>x</TableCell>
          </TableRow>
        </TableBody>
      </Table>
    )
    const scroller = container.querySelector('[data-slot="table-container"]')
    expect(scroller).toHaveAttribute('tabindex', '0')
    expect(scroller).toHaveAttribute('role', 'region')
    expect(screen.getByRole('region', { name: 'Table, scrollable' })).toBe(scroller)
  })
})
