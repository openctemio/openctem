/**
 * The tab panel is a keyboard stop (Tab after the strip): it shows the focus
 * ring every other stop shows, and only for keyboard focus.
 */
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../tabs'

describe('TabsContent', () => {
  it('is reached by the keyboard and draws a focus-visible ring', async () => {
    render(
      <Tabs defaultValue="a">
        <TabsList>
          <TabsTrigger value="a">Overview</TabsTrigger>
          <TabsTrigger value="b">Details</TabsTrigger>
        </TabsList>
        <TabsContent value="a">Panel text</TabsContent>
      </Tabs>
    )
    await userEvent.tab()
    expect(screen.getByRole('tab', { name: 'Overview' })).toHaveFocus()
    await userEvent.tab()
    const panel = screen.getByRole('tabpanel')
    expect(panel).toHaveFocus()
    expect(panel).toHaveClass('focus-visible:ring-2', 'focus-visible:ring-ring')
    expect(panel).not.toHaveClass('focus-visible:outline-none')
  })
})
