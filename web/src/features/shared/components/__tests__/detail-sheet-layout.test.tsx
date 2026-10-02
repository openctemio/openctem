import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, render, renderHook, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { KeyRound, Trash2 } from 'lucide-react'

import {
  DetailHeader,
  DetailSheet,
  DetailTabs,
  useDetailTab,
  type DetailMenuItem,
} from '../detail-sheet-layout'

function renderSheet(props: Partial<React.ComponentProps<typeof DetailHeader>> = {}) {
  const onClose = vi.fn()
  render(
    <DetailSheet
      open
      onOpenChange={() => {}}
      header={<DetailHeader title="dmz-scanner-01" onClose={onClose} {...props} />}
      tabs={
        <DetailTabs
          tabs={[
            { value: 'overview', label: 'Overview' },
            { value: 'jobs', label: 'Jobs' },
          ]}
          value="overview"
          onValueChange={() => {}}
        />
      }
      panel="overview"
    >
      <p>Body</p>
    </DetailSheet>
  )
  return { onClose }
}

describe('DetailSheet + DetailHeader', () => {
  it('is a dialog named by the title, with the body as the tab panel', () => {
    renderSheet()
    expect(screen.getByRole('dialog', { name: 'dmz-scanner-01' })).toBeInTheDocument()
    expect(screen.getByRole('tabpanel', { name: 'overview' })).toHaveTextContent('Body')
  })

  it('wraps a long title instead of cutting it', () => {
    const long = 'a-very-long-sensor-name-that-is-the-only-identifier-on-screen-'.repeat(3)
    renderSheet({ title: long })
    const title = screen.getByRole('heading', { name: long })
    expect(title.className).toContain('break-words')
    expect(title.className).not.toContain('truncate')
  })

  it('joins the meta parts with a middle dot and skips empty ones', () => {
    renderSheet({ meta: ['Scanner · long-running', null, '', '10.0.0.5'] })
    expect(screen.getByText('Scanner · long-running · 10.0.0.5')).toBeInTheDocument()
  })

  it('renders the action row', () => {
    renderSheet({ actions: <button>Edit</button> })
    expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument()
  })

  it('closes from the close button', async () => {
    const { onClose } = renderSheet()
    // The Sheet's built-in close button is hidden by CSS; ours is in the header.
    const header = document.querySelector('[data-slot="detail-header"]') as HTMLElement
    await userEvent.click(within(header).getByRole('button', { name: 'Close' }))
    expect(onClose).toHaveBeenCalled()
  })

  it('has no ⋯ menu without items', () => {
    renderSheet({ menu: [] })
    expect(screen.queryByRole('button', { name: 'More actions' })).not.toBeInTheDocument()
  })

  it('lists menu items, destructive ones in the destructive colour after a divider', async () => {
    const rotate = vi.fn()
    const menu: DetailMenuItem[] = [
      { label: 'Rotate key', icon: KeyRound, onSelect: rotate },
      {
        label: 'Delete',
        icon: Trash2,
        destructive: true,
        separatorBefore: true,
        onSelect: vi.fn(),
      },
    ]
    renderSheet({ menu })
    await userEvent.click(screen.getByRole('button', { name: 'More actions' }))
    expect(await screen.findByRole('menuitem', { name: 'Delete' })).toHaveClass('text-destructive')
    expect(screen.getByRole('separator')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('menuitem', { name: 'Rotate key' }))
    expect(rotate).toHaveBeenCalled()
  })
})

describe('DetailTabs', () => {
  it('changes tab with the arrow keys', async () => {
    const onChange = vi.fn()
    render(
      <DetailTabs
        tabs={[
          { value: 'overview', label: 'Overview' },
          { value: 'jobs', label: 'Jobs' },
        ]}
        value="overview"
        onValueChange={onChange}
      />
    )
    screen.getByRole('tab', { name: 'Overview' }).focus()
    await userEvent.keyboard('{ArrowRight}')
    expect(onChange).toHaveBeenCalledWith('jobs')
  })
})

describe('useDetailTab', () => {
  beforeEach(() => window.history.replaceState(null, '', '/sensors'))

  it('starts on the first tab and writes others to the URL', () => {
    const { result } = renderHook(() => useDetailTab('view', ['overview', 'jobs'] as const))
    expect(result.current[0]).toBe('overview')
    act(() => result.current[1]('jobs'))
    expect(new URLSearchParams(window.location.search).get('view')).toBe('jobs')
  })

  it('ignores a value that names no tab', () => {
    window.history.replaceState(null, '', '/sensors?view=bogus')
    const { result } = renderHook(() => useDetailTab('view', ['overview', 'jobs'] as const))
    expect(result.current[0]).toBe('overview')
  })
})
