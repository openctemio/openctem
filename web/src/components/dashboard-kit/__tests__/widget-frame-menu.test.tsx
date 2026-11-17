import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ChartOrTable } from '../viz-parts'
import { WidgetFrame } from '../widget-frame'
import type { WidgetState } from '../types'

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), prefetch: vi.fn() }),
  usePathname: () => '/',
}))

const BODY = <ChartOrTable chart={<p>the-chart</p>} table={<p>the-table</p>} summary="Rising" />

function frame(state: WidgetState, extra: Partial<React.ComponentProps<typeof WidgetFrame>> = {}) {
  return render(
    <WidgetFrame title="New vs fixed" state={state} {...extra}>
      {BODY}
    </WidgetFrame>
  )
}

const openMenu = () =>
  userEvent.click(screen.getByRole('button', { name: 'Actions for New vs fixed' }))

describe('WidgetFrame menu', () => {
  it('has one menu button and no switch of its own in the body', () => {
    frame('ready', { definition: 'Counted daily.' })
    expect(screen.getAllByRole('button')).toHaveLength(1)
    expect(screen.getByRole('button', { name: 'Actions for New vs fixed' })).toBeInTheDocument()
    expect(screen.getByText('the-chart')).toBeInTheDocument()
  })

  it('a lone item is a button, not a menu of one', async () => {
    const { container } = frame('ready')
    expect(screen.queryByRole('button', { name: 'Actions for New vs fixed' })).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Show table' }))
    expect(screen.getByText('the-table')).toBeInTheDocument()
    expect(container.querySelector('section')).toHaveAttribute('data-view', 'table')
    await userEvent.click(screen.getByRole('button', { name: 'Show chart' }))
    expect(screen.getByText('the-chart')).toBeInTheDocument()
  })

  it('a lone list is a link', () => {
    render(
      <WidgetFrame title="Open findings" state="ready" listHref="/findings?state=open">
        <p>12</p>
      </WidgetFrame>
    )
    expect(screen.getByRole('link', { name: 'Open list' })).toHaveAttribute(
      'href',
      '/findings?state=open'
    )
  })

  it('switches the body between chart and table from the menu', async () => {
    const { container } = frame('ready', { definition: 'Counted daily.' })
    await openMenu()
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Show table' }))
    expect(screen.getByText('the-table')).toBeInTheDocument()
    expect(screen.queryByText('the-chart')).toBeNull()
    expect(container.querySelector('section')).toHaveAttribute('data-view', 'table')
    await openMenu()
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Show chart' }))
    expect(screen.getByText('the-chart')).toBeInTheDocument()
  })

  it('opens the list the figure counts, internal paths only', async () => {
    const { unmount } = frame('ready', { listHref: '/findings?state=open' })
    await openMenu()
    expect(await screen.findByRole('menuitem', { name: 'Open list' })).toHaveAttribute(
      'href',
      '/findings?state=open'
    )
    unmount()
    frame('ready', { listHref: 'https://example.com/x', definition: 'Counted daily.' })
    await openMenu()
    expect(await screen.findByRole('menuitem', { name: 'Show table' })).toBeInTheDocument()
    expect(screen.queryByRole('menuitem', { name: 'Open list' })).toBeNull()
  })

  it('shows how the figure is counted inside the frame, and closes it', async () => {
    frame('ready', { definition: 'Open findings in your scope.' })
    expect(screen.queryByText('Open findings in your scope.')).toBeNull()
    await openMenu()
    await userEvent.click(await screen.findByRole('menuitem', { name: 'How this is counted' }))
    expect(screen.getByTestId('widget-definition')).toHaveTextContent(
      'Open findings in your scope.'
    )
    await userEvent.click(screen.getByRole('button', { name: 'Close how this is counted' }))
    expect(screen.queryByText('Open findings in your scope.')).toBeNull()
  })

  it('a state without figures offers neither the list nor the table', async () => {
    frame('error', { listHref: '/findings', definition: 'Counted daily.', onRetry: vi.fn() })
    expect(screen.getByRole('button', { name: 'How this is counted' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Actions for New vs fixed' })).toBeNull()
    expect(screen.queryByRole('link', { name: 'Open list' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Show table' })).toBeNull()
  })

  it('has no menu button when nothing applies, or when the host turns it off', () => {
    const { unmount } = render(
      <WidgetFrame title="Note" state="ready">
        <p>text</p>
      </WidgetFrame>
    )
    expect(screen.queryByRole('button')).toBeNull()
    unmount()
    frame('ready', { definition: 'Counted daily.', menu: false })
    expect(screen.queryByRole('button', { name: 'Actions for New vs fixed' })).toBeNull()
  })

  it("adds the host's items after its own, destructive last", async () => {
    const onRemove = vi.fn()
    frame('ready', {
      listHref: '/findings',
      menuItems: [
        { id: 'remove', label: 'Remove', destructive: true, onSelect: onRemove },
        { id: 'edit', label: 'Edit widget', onSelect: vi.fn() },
      ],
    })
    await openMenu()
    const names = (await screen.findAllByRole('menuitem')).map((el) => el.textContent)
    expect(names).toEqual(['Open list', 'Show table', 'Edit widget', 'Remove'])
    await userEvent.click(screen.getByRole('menuitem', { name: 'Remove' }))
    expect(onRemove).toHaveBeenCalled()
  })

  it('outside a frame the visualization keeps its own switch', async () => {
    render(BODY)
    await userEvent.click(screen.getByRole('button', { name: 'Show table' }))
    expect(screen.getByText('the-table')).toBeInTheDocument()
  })
})
