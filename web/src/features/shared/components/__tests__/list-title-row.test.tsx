import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

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

  it('a total that could not be counted says so, never a number, with Retry', () => {
    const onRetry = vi.fn()
    render(<ListCount total={0} failed onRetry={onRetry} label="0 findings" />)
    const count = screen.getByRole('status')
    expect(count).toHaveAttribute('data-slot', 'list-count')
    expect(count).toHaveAttribute('data-state', 'failed')
    expect(count).toHaveTextContent('Could not count')
    // The short form a phone shows; the full sentence is the tooltip.
    expect(count).toHaveTextContent('Not counted')
    expect(count).toHaveAttribute('title', 'The total could not be counted. Try again.')
    expect(count).not.toHaveTextContent('0')
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(onRetry).toHaveBeenCalledTimes(1)
    // One count slot on the page, as the page-anatomy check asks.
    expect(document.querySelectorAll('[data-slot=list-count]')).toHaveLength(1)
  })

  it('a failed count without a retry handler has no Retry', () => {
    render(<ListCount total={0} failed />)
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })
})

describe('ListTitleRow', () => {
  it('is read to assistive technology only on a phone when it can only show the name and count', () => {
    const { container, rerender } = render(<ListTitleRow title="All" count={<span>5</span>} />)
    const row = container.querySelector('[data-slot="list-title-row"]')!
    expect(row).toHaveClass('max-md:sr-only')
    // Actions or a start slot (a Modified mark can appear there): the row keeps its place.
    rerender(
      <ListTitleRow title="All" count={<span>5</span>} start={null}>
        <button type="button">Refresh</button>
      </ListTitleRow>
    )
    expect(container.querySelector('[data-slot="list-title-row"]')).not.toHaveClass(
      'max-md:sr-only'
    )
    // Actions drawn only on wide screens (`{!isPhone && ...}`) still keep the
    // row: a Modified mark appearing later must not move the toolbar.
    rerender(
      <ListTitleRow title="All" count={<span>5</span>}>
        {false}
      </ListTitleRow>
    )
    expect(container.querySelector('[data-slot="list-title-row"]')).not.toHaveClass(
      'max-md:sr-only'
    )
  })
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
    expect(screen.getByText('after').closest('[data-slot=list-title-start]')).not.toBeNull()
    expect(screen.getByRole('button', { name: 'Refresh' }).parentElement).toHaveAttribute(
      'data-slot',
      'list-title-end'
    )
  })

  it('a hidden name stays the heading for assistive technology, without a tooltip', () => {
    render(
      <ListTitleRow title="Assigned to me" titleHidden start={<span>what it holds</span>}>
        <button type="button">Refresh</button>
      </ListTitleRow>
    )
    const heading = screen.getByRole('heading', { level: 2, name: 'Assigned to me' })
    expect(heading).toHaveClass('sr-only')
    expect(heading).not.toHaveAttribute('title')
    expect(screen.getByText('what it holds')).toBeVisible()
  })

  it('a hidden name is drawn once the row has a count: a count never stands alone', () => {
    render(
      <ListTitleRow
        title="Rejected requests"
        titleHidden
        count={<span data-slot="list-count">4</span>}
      />
    )
    const heading = screen.getByRole('heading', { level: 2, name: 'Rejected requests' })
    expect(heading).not.toHaveClass('sr-only')
    expect(heading.parentElement).toContainElement(screen.getByText('4'))
  })
})

describe('ListViewChanged', () => {
  it('draws nothing while the view is unchanged', () => {
    const { container } = render(
      <ListViewChanged changed={false} onSave={() => {}} onReset={() => {}} />
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('shows Modified, then one Save view menu with Save view and Reset, on a changed view', async () => {
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
    // One button, so a narrow title row keeps room for the view's name.
    const names = Array.from(container.querySelectorAll('button')).map((b) => b.textContent)
    expect(names).toEqual(['Save view'])
    await userEvent.click(screen.getByRole('button', { name: 'Save view' }))
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Save view' }))
    expect(onSave).toHaveBeenCalledTimes(1)
    await userEvent.click(screen.getByRole('button', { name: 'Save view' }))
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Reset' }))
    expect(onReset).toHaveBeenCalledTimes(1)
  })

  it('offers Save changes and Save as new view to the owner of a saved view', async () => {
    const onSaveChanges = vi.fn()
    render(
      <ListViewChanged changed onSave={() => {}} onSaveChanges={onSaveChanges} onReset={() => {}} />
    )
    await userEvent.click(screen.getByRole('button', { name: 'Save view' }))
    const items = (await screen.findAllByRole('menuitem')).map((i) => i.textContent)
    expect(items).toEqual(['Save changes', 'Save as new view…', 'Reset'])
    await userEvent.click(screen.getByRole('menuitem', { name: 'Save changes' }))
    expect(onSaveChanges).toHaveBeenCalledTimes(1)
  })

  it('is a plain Reset for someone who may not save, and folds where the page says', () => {
    const { rerender } = render(<ListViewChanged changed onReset={() => {}} />)
    expect(screen.queryByRole('button', { name: 'Save view' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Reset' })).toBeInTheDocument()
    rerender(
      <ListViewChanged changed onSave={() => {}} onReset={() => {}} actionsClassName="hidden" />
    )
    expect(screen.queryByRole('button', { name: 'Reset' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Save view' }).parentElement).toHaveClass('hidden')
  })
})
