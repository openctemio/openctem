import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { List } from 'lucide-react'
import { TooltipProvider } from '@/components/ui/tooltip'
import { PageHeader } from '../page-header'
import { ViewSwitcher } from '../view-switcher'

const options = [
  { value: 'a', label: 'List view', icon: List },
  { value: 'b', label: 'Category view', icon: List },
] as const

describe('PageHeader view switcher slot', () => {
  it('puts the switcher in its own slot, apart from the actions, ordered for phone and desktop', () => {
    render(
      <TooltipProvider>
        <PageHeader
          title="Assets"
          viewSwitcher={<ViewSwitcher options={options} value="a" onChange={() => {}} />}
        >
          <button>Export</button>
          <button>Add asset</button>
        </PageHeader>
      </TooltipProvider>
    )
    const header = document.querySelector('[data-slot="page-header"]') as HTMLElement
    const slot = header.querySelector('[data-slot="page-header-view-switcher"]') as HTMLElement
    expect(slot).toContainElement(screen.getByRole('group', { name: 'View' }))
    expect(slot).not.toContainElement(screen.getByText('Export'))
    expect(slot).toHaveClass('order-2', 'sm:order-3', 'shrink-0')
    const actions = screen.getByText('Export').parentElement as HTMLElement
    expect(actions).not.toContainElement(slot)
    // Phone: actions wrap to a full row under the title; desktop: left of the switcher.
    expect(actions).toHaveClass('order-3', 'basis-full', 'sm:order-2', 'sm:basis-auto')
    // Secondary before primary.
    expect(
      screen.getByText('Export').compareDocumentPosition(screen.getByText('Add asset')) &
        Node.DOCUMENT_POSITION_FOLLOWING
    ).toBeTruthy()
  })

  it('leaves the header unchanged without a switcher', () => {
    render(
      <PageHeader title="Scans">
        <button>Run</button>
      </PageHeader>
    )
    expect(document.querySelector('[data-slot="page-header-view-switcher"]')).toBeNull()
    expect(screen.getByText('Run').parentElement).not.toHaveClass('basis-full')
  })

  it('keeps pressed semantics and calls onChange', () => {
    const picked: string[] = []
    render(
      <TooltipProvider>
        <ViewSwitcher options={options} value="a" onChange={(v) => picked.push(v)} />
      </TooltipProvider>
    )
    expect(screen.getByRole('button', { name: 'List view' })).toHaveAttribute(
      'aria-pressed',
      'true'
    )
    const other = screen.getByRole('button', { name: 'Category view' })
    expect(other).toHaveAttribute('aria-pressed', 'false')
    other.click()
    expect(picked).toEqual(['b'])
  })
})
