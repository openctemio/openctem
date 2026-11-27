import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'

import { Button } from '@/components/ui/button'
import {
  DetailFold,
  DetailPageHeader,
  DetailPosition,
  DetailSectionBlock,
  DetailSectionList,
  PropertyFold,
  PropertyGroup,
  PropertyList,
  PropertyRow,
} from '..'

describe('DetailPageHeader', () => {
  const parent = { href: '/findings?view=open', label: 'Findings' }

  it('renders one h1, the chips, the way back and the actions in reading order', () => {
    render(
      <DetailPageHeader
        title="Session token leak"
        parent={parent}
        chips={<span>Vulnerability</span>}
        menu={[
          { id: 'copy', label: 'Copy link', onSelect: () => {} },
          { id: 'id', label: 'Copy ID', onSelect: () => {} },
        ]}
        secondary={<Button variant="outline">Retest</Button>}
        primary={<Button>Add to task</Button>}
      />
    )
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1)
    expect(screen.getByRole('heading', { level: 1, name: 'Session token leak' })).toHaveAttribute(
      'id',
      'page-title'
    )
    expect(screen.getByText('Vulnerability')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Findings' })).toHaveAttribute(
      'href',
      '/findings?view=open'
    )
    const actions = document.querySelector('[data-slot="detail-actions"]') as HTMLElement
    const names = within(actions)
      .getAllByRole('button')
      .map((b) => b.getAttribute('aria-label') ?? b.textContent)
    expect(names).toEqual(['More actions', 'Retest', 'Add to task'])
  })

  it('never lets the main action shrink below its label on a phone (the row wraps)', () => {
    render(
      <DetailPageHeader title="A record" parent={parent} primary={<Button>Create task</Button>} />
    )
    const primary = document.querySelector('[data-slot="detail-primary"]') as HTMLElement
    expect(primary.className).toContain('max-md:min-w-fit')
    expect(primary.className).not.toContain('max-md:min-w-0')
  })

  it('keeps a lone More on the title line on a phone; buttons take their own row', () => {
    const menu = [
      { id: 'a', label: 'Copy link', onSelect: () => {} },
      { id: 'b', label: 'Copy ID', onSelect: () => {} },
    ]
    const { unmount } = render(<DetailPageHeader title="A record" parent={parent} menu={menu} />)
    let actions = document.querySelector('[data-slot="detail-actions"]') as HTMLElement
    expect(actions.className).not.toContain('max-md:w-full')
    expect(screen.getByRole('heading', { level: 1 }).className).toContain('max-md:basis-0')
    unmount()
    render(
      <DetailPageHeader
        title="A record"
        parent={parent}
        menu={menu}
        primary={<Button>Add to task</Button>}
      />
    )
    actions = document.querySelector('[data-slot="detail-actions"]') as HTMLElement
    expect(actions.className).toContain('max-md:w-full')
    expect(screen.getByRole('heading', { level: 1 }).className).not.toContain('max-md:basis-0')
  })

  it('is the page-header block of the page stack', () => {
    const { container } = render(<DetailPageHeader title="A record" parent={parent} />)
    expect(container.querySelector('header[data-slot="page-header"]')).not.toBeNull()
  })

  it('draws no More button without menu items and no action row without actions', () => {
    render(<DetailPageHeader title="A record" parent={parent} menu={[]} />)
    expect(screen.queryByRole('button', { name: 'More actions' })).toBeNull()
    expect(document.querySelector('[data-slot="detail-actions"]')).toBeNull()
  })

  it('shows the position on the back row and on the chip row (one per width)', () => {
    render(
      <DetailPageHeader
        title="A record"
        parent={parent}
        position={<span data-testid="pos">2 of 27</span>}
      />
    )
    // The same control is placed twice; CSS shows one of them per width.
    expect(screen.getAllByTestId('pos')).toHaveLength(2)
  })
})

describe('DetailPosition', () => {
  it('links to the neighbours and back to the list', () => {
    render(
      <DetailPosition
        label="2 of 27"
        listHref="/findings?view=open"
        listLabel="Open findings"
        prevHref="/findings/a"
        nextHref="/findings/c"
        prevLabel="Previous finding (k)"
        nextLabel="Next finding (j)"
      />
    )
    expect(screen.getByRole('link', { name: 'Previous finding (k)' })).toHaveAttribute(
      'href',
      '/findings/a'
    )
    expect(screen.getByRole('link', { name: 'Next finding (j)' })).toHaveAttribute(
      'href',
      '/findings/c'
    )
    const count = screen.getByRole('link', { name: '2 of 27' })
    expect(count).toHaveAttribute('href', '/findings?view=open')
    expect(count).toHaveAttribute('title', 'Open findings')
  })

  it('disables a step at the end of the list', () => {
    render(
      <DetailPosition
        label="1 of 27"
        nextHref="/findings/b"
        prevLabel="Previous finding (k)"
        nextLabel="Next finding (j)"
      />
    )
    expect(screen.getByRole('button', { name: 'Previous finding (k)' })).toBeDisabled()
    expect(screen.queryByRole('link', { name: '1 of 27' })).toBeNull()
  })

  it('never turns a script URL into a link', () => {
    render(
      <DetailPosition
        label="1 of 2"
        listHref="javascript:alert(1)"
        prevLabel="Previous"
        nextLabel="Next"
      />
    )
    expect(screen.queryByRole('link', { name: '1 of 2' })).toBeNull()
  })
})

describe('PropertyList', () => {
  it('is a named group of description lists with dt/dd pairs', () => {
    render(
      <PropertyList label="Properties">
        <PropertyGroup>
          <PropertyRow label="Status">Confirmed</PropertyRow>
        </PropertyGroup>
        <PropertyGroup caption="People">
          <PropertyRow label="Assignee">Sam Rivera</PropertyRow>
        </PropertyGroup>
      </PropertyList>
    )
    const group = screen.getByRole('group', { name: 'Properties' })
    expect(group.querySelectorAll('dl')).toHaveLength(2)
    const term = screen.getByText('Status')
    expect(term.tagName).toBe('DT')
    expect(term.nextElementSibling?.tagName).toBe('DD')
    expect(term.nextElementSibling).toHaveTextContent('Confirmed')
    // The caption names its group.
    expect(within(group).getByRole('group', { name: 'People' })).toContainElement(
      screen.getByText('Assignee')
    )
  })

  it('keeps a phone row with a control at 44 px: little padding, more for a value of several lines', () => {
    const { container } = render(
      <PropertyList label="Properties">
        <PropertyGroup>
          <PropertyRow label="Status">
            <button type="button">Confirmed</button>
          </PropertyRow>
          <PropertyRow label="Description" top>
            Two lines of text
          </PropertyRow>
        </PropertyGroup>
      </PropertyList>
    )
    const [control, text] = Array.from(
      container.querySelectorAll<HTMLElement>('[data-slot=property-row]')
    )
    // 2 + 36 + 2 + 1 (rule) = 41, so the row is the 44 px minimum.
    expect(control.className).toContain('max-md:min-h-touch-target')
    expect(control.className).toContain('max-md:py-0.5')
    expect(control.className).not.toContain('max-md:py-1.5')
    expect(text.className).toContain('max-md:py-1.5')
  })

  it('puts a value that does not fit beside its label under it, never cut', () => {
    const { container } = render(
      <PropertyList label="Properties">
        <PropertyGroup>
          <PropertyRow label="Assignee">e2e-owner-1795641209@openctem-test.local</PropertyRow>
        </PropertyGroup>
      </PropertyList>
    )
    const row = container.querySelector<HTMLElement>('[data-slot=property-row]')!
    // From 768 px: a wrapping row, the label a fixed column, the value the
    // rest of the line at its own width (it wraps to a line of its own).
    expect(row.className).toContain('md:flex-wrap')
    expect(row.querySelector('dt')!.className).toContain('md:w-[6.75rem]')
    expect(row.querySelector('dd')!.className).toContain('md:flex-[1_1_auto]')
    expect(row.querySelector('dd')!.className).not.toContain('truncate')
  })

  it('renders no row for an empty value', () => {
    render(
      <PropertyList label="Properties">
        <PropertyGroup>
          <PropertyRow label="Resolved">{null}</PropertyRow>
          <PropertyRow label="Tags">{''}</PropertyRow>
          <PropertyRow label="Seen in">{0}</PropertyRow>
        </PropertyGroup>
      </PropertyList>
    )
    expect(screen.queryByText('Resolved')).toBeNull()
    expect(screen.queryByText('Tags')).toBeNull()
    // Zero is a value.
    expect(screen.getByText('Seen in')).toBeInTheDocument()
  })

  it('folds the tail behind a button that says what it holds', () => {
    render(
      <PropertyList label="Properties">
        <PropertyFold label="Asset, dates and more" openLabel="Fewer details">
          <PropertyGroup>
            <PropertyRow label="Asset">vpn.example.com</PropertyRow>
          </PropertyGroup>
        </PropertyFold>
      </PropertyList>
    )
    const toggle = screen.getByRole('button', { name: 'Asset, dates and more' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    const body = document.getElementById(toggle.getAttribute('aria-controls') as string)
    // The rows stay in the document (hidden below 768 px by a class only).
    expect(body).toContainElement(screen.getByText('Asset'))
    expect(body?.className).toContain('max-md:hidden')
    fireEvent.click(toggle)
    expect(screen.getByRole('button', { name: 'Fewer details' })).toHaveAttribute(
      'aria-expanded',
      'true'
    )
    expect(body?.className).not.toContain('max-md:hidden')
  })
})

describe('DetailSectionBlock', () => {
  it('is a section named by its h2, with the count and the end controls', () => {
    const add = vi.fn()
    render(
      <DetailSectionList>
        <DetailSectionBlock
          title="Notes"
          count={3}
          mark={<span>Suggested by AI</span>}
          actions={<Button onClick={add}>Add evidence</Button>}
        >
          <p>body</p>
        </DetailSectionBlock>
      </DetailSectionList>
    )
    const section = screen.getByRole('region', { name: 'Notes' })
    expect(within(section).getByRole('heading', { level: 2, name: 'Notes' })).toBeInTheDocument()
    expect(within(section).getByRole('img', { name: '3 items' })).toBeInTheDocument()
    expect(within(section).getByText('Suggested by AI')).toBeInTheDocument()
    fireEvent.click(within(section).getByRole('button', { name: 'Add evidence' }))
    expect(add).toHaveBeenCalledOnce()
  })

  it('renders no body wrapper for a title-only block', () => {
    const { container } = render(<DetailSectionBlock title="Linked findings" count={0} />)
    expect(container.querySelector('[data-slot="detail-section-body"]')).toBeNull()
  })
})

describe('DetailFold', () => {
  it('keeps its content closed until asked for, and says what is inside', () => {
    render(
      <DetailFold label="How this was scored" note="score 13.5 of 15">
        <p>formula</p>
      </DetailFold>
    )
    const details = document.querySelector('details') as HTMLDetailsElement
    expect(details.open).toBe(false)
    expect(screen.getByText('How this was scored').closest('summary')).not.toBeNull()
    expect(screen.getByText('score 13.5 of 15')).toBeInTheDocument()
  })

  it('opens at once when asked to', () => {
    render(
      <DetailFold label="Retest check" defaultOpen>
        <p>check</p>
      </DetailFold>
    )
    expect((document.querySelector('details') as HTMLDetailsElement).open).toBe(true)
  })
})
