import { describe, expect, it } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

import { useHeldRows } from '../use-held-rows'

type Row = { id: string; status: string }
const getId = (r: Row) => r.id

function List({ rows, viewKey = 'v1' }: { rows: Row[]; viewKey?: string }) {
  const held = useHeldRows(rows, getId, viewKey)
  return (
    <div data-testid="list" data-held={held.held ? 'true' : undefined} {...held.bind}>
      <p data-testid="toolbar">toolbar</p>
      <table>
        <tbody>
          {held.rows.map((r) => (
            <tr key={r.id}>
              <td>
                {r.id}:{r.status}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

const shown = () => screen.getAllByRole('row').map((r) => r.textContent)
const A: Row = { id: 'a', status: 'running' }
const B: Row = { id: 'b', status: 'pending' }
const C: Row = { id: 'c', status: 'pending' }

describe('useHeldRows', () => {
  it('shows the rows as read while the pointer is elsewhere', () => {
    const { rerender } = render(<List rows={[A, B]} />)
    rerender(<List rows={[C, A, B]} />)
    expect(shown()).toEqual(['c:pending', 'a:running', 'b:pending'])
  })

  it('does not hold while the pointer is on the toolbar', () => {
    const { rerender } = render(<List rows={[A, B]} />)
    fireEvent.pointerOver(screen.getByTestId('toolbar'))
    rerender(<List rows={[C, A, B]} />)
    expect(shown()).toEqual(['c:pending', 'a:running', 'b:pending'])
  })

  it('keeps the rows in place under the pointer and gives each its fresh values', () => {
    const { rerender } = render(<List rows={[A, B]} />)
    fireEvent.pointerOver(screen.getByText('a:running'))
    expect(screen.getByTestId('list')).toHaveAttribute('data-held', 'true')
    // A re-read: a new run first, and the first run finished.
    rerender(<List rows={[C, { ...A, status: 'completed' }, B]} />)
    expect(shown()).toEqual(['a:completed', 'b:pending'])
    // A row the re-read no longer returns stays as it was.
    rerender(<List rows={[C, { ...A, status: 'completed' }]} />)
    expect(shown()).toEqual(['a:completed', 'b:pending'])
  })

  it('shows the list as read once the pointer leaves it', () => {
    const { rerender } = render(<List rows={[A, B]} />)
    fireEvent.pointerOver(screen.getByText('a:running'))
    rerender(<List rows={[C, A, B]} />)
    fireEvent.pointerLeave(screen.getByTestId('list'))
    expect(shown()).toEqual(['c:pending', 'a:running', 'b:pending'])
    expect(screen.getByTestId('list')).not.toHaveAttribute('data-held')
  })

  it('shows a new page, filter or sort at once, pointer or not', () => {
    const { rerender } = render(<List rows={[A, B]} />)
    fireEvent.pointerOver(screen.getByText('a:running'))
    rerender(<List rows={[C]} viewKey="v2" />)
    expect(shown()).toEqual(['c:pending'])
  })
})
