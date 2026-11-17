import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

import { ListCount, ListTitleRow, ListViewChanged } from '../list-title-row'

describe('ListCount', () => {
  it('is one polite, atomic region read as the sentence the page gives', () => {
    render(<ListCount total={1234} label="1,234 findings" />)
    const count = screen.getByRole('status')
    expect(count).toHaveAttribute('data-slot', 'list-count')
    expect(count).toHaveAttribute('aria-live', 'polite')
    expect(count).toHaveAttribute('aria-atomic', 'true')
    expect(count).toHaveTextContent('1,234')
    expect(count.querySelector('.sr-only')).toHaveTextContent('1,234 findings')
  })

  it('shows a partial count with "+" and says so in its tooltip', () => {
    render(<ListCount total={1000} capped />)
    const count = screen.getByRole('status')
    expect(count).toHaveTextContent('1,000+')
    expect(count).toHaveAttribute('title', 'Counted in your data scope. Counted up to this number.')
  })

  it('is a 20 px pill on the raised surface that says what was counted', () => {
    render(<ListCount total={418} label="418 findings" />)
    const count = screen.getByRole('status')
    expect(count).toHaveAttribute('title', 'Counted in your data scope')
    expect(count).toHaveClass('h-5', 'rounded-full', 'bg-surface-raised', 'text-cap-m')
    expect(count).toHaveClass('text-muted-foreground')
  })

  it('keeps its place, empty, while the count is not known', () => {
    render(<ListCount total={0} loading label="0 findings" />)
    const count = screen.getByRole('status')
    expect(count).toBeEmptyDOMElement()
    // No empty pill and no tooltip before there is a number.
    expect(count).not.toHaveClass('bg-surface-raised')
    expect(count).not.toHaveAttribute('title')
  })
})

describe('ListTitleRow', () => {
  it('puts the name and the count first, the list actions at the end', () => {
    render(
      <ListTitleRow title="All assets" count={<ListCount total={3} />}>
        <button type="button">Refresh</button>
      </ListTitleRow>
    )
    expect(screen.getByRole('heading', { level: 2, name: 'All assets' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Refresh' }).parentElement).toHaveClass('ms-auto')
  })

  it('marks its start and end groups and hands out the row and the name', () => {
    let row: HTMLDivElement | null = null
    render(
      <ListTitleRow
        ref={(el) => {
          row = el
        }}
        title="Active"
        titleTestId="view-name"
        className="@container/actions"
        start={<span>after</span>}
      >
        <button type="button">Refresh</button>
      </ListTitleRow>
    )
    expect(row).toHaveAttribute('data-slot', 'list-title-row')
    expect(row).toHaveClass('@container/actions')
    expect(screen.getByTestId('view-name')).toHaveTextContent('Active')
    expect(screen.getByText('after').parentElement).toHaveAttribute('data-slot', 'list-title-start')
    expect(screen.getByRole('button', { name: 'Refresh' }).parentElement).toHaveAttribute(
      'data-slot',
      'list-title-end'
    )
  })
})

describe('ListViewChanged', () => {
  it('draws nothing while the view is unchanged', () => {
    const { container } = render(
      <ListViewChanged changed={false} onSave={() => {}} onReset={() => {}} />
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('shows Modified, then Save view and Reset, on a changed view', () => {
    const onSave = vi.fn()
    const onReset = vi.fn()
    const { container } = render(
      <ListViewChanged changed summary="1 filter added" onSave={onSave} onReset={onReset} />
    )
    const lozenge = container.querySelector('[data-slot="list-modified"]')!
    expect(lozenge).toHaveTextContent('Modified')
    expect(lozenge).toHaveAttribute('title', '1 filter added')
    // 20 px with its dashed border, 12/16, muted.
    expect(lozenge).toHaveClass(
      'h-5',
      'border',
      'border-dashed',
      'text-cap',
      'text-muted-foreground'
    )
    const names = Array.from(container.querySelectorAll('button')).map((b) => b.textContent)
    expect(names).toEqual(['Save view', 'Reset'])
    fireEvent.click(screen.getByRole('button', { name: 'Save view' }))
    fireEvent.click(screen.getByRole('button', { name: 'Reset' }))
    expect(onSave).toHaveBeenCalledTimes(1)
    expect(onReset).toHaveBeenCalledTimes(1)
  })

  it('leaves Save view out for someone who may not save, and takes a save menu', () => {
    const { rerender } = render(<ListViewChanged changed onReset={() => {}} />)
    expect(screen.queryByRole('button', { name: 'Save view' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Reset' })).toBeInTheDocument()
    rerender(
      <ListViewChanged
        changed
        onSave={() => {}}
        save={<button type="button">Save menu</button>}
        actionsClassName="hidden"
      />
    )
    expect(screen.queryByRole('button', { name: 'Save view' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Save menu' }).parentElement).toHaveClass('hidden')
  })
})
