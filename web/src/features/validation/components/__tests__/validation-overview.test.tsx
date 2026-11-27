/**
 * "Waiting for you" rows are list items: the count, the text taking the free
 * width, and the action at the row's end (under the text on a phone). Every
 * row's action is an outline button: no queue row is the page's main action.
 */
import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { WaitingForYou, type WaitingItem } from '../validation-overview'

const item = (key: string, count: number | undefined): WaitingItem => ({
  key,
  count,
  title: `Title ${key}`,
  reason: `Reason ${key}`,
  action: `Act ${key}`,
  href: `/x/${key}`,
})

describe('WaitingForYou', () => {
  it('lets the text take the free width so the action sits at the row end', () => {
    render(<WaitingForYou items={[item('a', 1), item('b', 4)]} starts={[]} />)
    const rows = within(screen.getByTestId('validation-waiting')).getAllByRole('listitem')
    expect(rows).toHaveLength(2)
    for (const row of rows) {
      // The text track grows (1fr); a capped track (32rem) left the action
      // floating mid-row on a wide card.
      expect(row.className).toContain('sm:grid-cols-[3.5rem_minmax(0,1fr)_auto]')
      expect(row.className).not.toMatch(/32rem|justify-start/)
      const action = within(row).getByRole('link')
      expect(action.className).toContain('sm:justify-self-end')
      // Phone: under the text, at its start.
      expect(action.className).toContain('col-start-2')
    }
  })

  it('draws every row action as an outline button, the first one too', () => {
    render(<WaitingForYou items={[item('a', 2), item('b', 3), item('c', 1)]} starts={[]} />)
    const links = within(screen.getByTestId('validation-waiting')).getAllByRole('link')
    expect(links.map((l) => l.getAttribute('data-variant'))).toEqual([
      'outline',
      'outline',
      'outline',
    ])
  })

  it('leaves out an empty queue', () => {
    render(<WaitingForYou items={[item('a', 0), item('b', 5)]} starts={[]} />)
    const rows = within(screen.getByTestId('validation-waiting')).getAllByRole('listitem')
    expect(rows).toHaveLength(1)
    expect(rows[0]).toHaveTextContent('5Title b')
  })
})
