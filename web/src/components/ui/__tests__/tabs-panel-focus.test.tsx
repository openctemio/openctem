/**
 * A tab panel that holds controls is not a keyboard stop and never draws a
 * ring around the whole panel (a list's toolbar and table sat in a teal frame
 * at rest). A panel of plain text opts in with `tabIndex={0}` and then shows
 * the ring for keyboard focus only.
 */
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../tabs'

function tabs(panelProps: { tabIndex?: number } = {}) {
  render(
    <Tabs defaultValue="a">
      <TabsList>
        <TabsTrigger value="a">Overview</TabsTrigger>
        <TabsTrigger value="b">Details</TabsTrigger>
      </TabsList>
      <TabsContent value="a" {...panelProps}>
        <button type="button">Refresh</button>
      </TabsContent>
    </Tabs>
  )
}

describe('TabsContent', () => {
  it('is skipped by Tab (its controls are the stops) and has no focus ring', async () => {
    tabs()
    await userEvent.tab()
    expect(screen.getByRole('tab', { name: 'Overview' })).toHaveFocus()
    await userEvent.tab()
    expect(screen.getByRole('button', { name: 'Refresh' })).toHaveFocus()
    const panel = screen.getByRole('tabpanel')
    expect(panel).toHaveAttribute('tabindex', '-1')
    expect(panel.className).not.toMatch(/ring/)
  })

  it('a panel with no control of its own can opt in as a keyboard stop with a focus-visible ring', async () => {
    tabs({ tabIndex: 0 })
    await userEvent.tab()
    await userEvent.tab()
    const panel = screen.getByRole('tabpanel')
    expect(panel).toHaveFocus()
    expect(panel).toHaveClass('focus-visible:ring-2', 'focus-visible:ring-ring')
  })
})
