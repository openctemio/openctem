import { beforeEach, describe, expect, it, vi } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ArrowRightLeft } from 'lucide-react'

// The real sanitising renderer, without next/dynamic's async loading.
vi.mock('@/components/ui/markdown-editor', async () => {
  const { default: MDEditor } = await import('@uiw/react-md-editor')
  const { markdownPreviewSecurityProps } = await import('@/lib/sanitize-markdown')
  return {
    MarkdownPreview: ({ content }: { content: string }) => (
      <div data-testid="md">
        <MDEditor.Markdown source={content} {...markdownPreviewSecurityProps} />
      </div>
    ),
  }
})
vi.mock('@/hooks/use-display-user', () => ({
  useDisplayUser: () => ({ id: 'u-me', name: 'Me Myself', email: 'me@example.test' }),
}))

// Radix tooltips measure themselves; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

import { EntityActivity } from '../entity-activity'
import type { ActivityItem } from '../../types'

// The fixtures span five hours and the feed never folds a run across a day
// separator, so "now" for the fixtures is moved to just before today's
// midnight when the suite runs in the first hours of the day (CI in UTC):
// otherwise the run of three changes splits at midnight and does not fold.
function fixtureNow(): number {
  const now = new Date()
  if (now.getHours() >= 6) return now.getTime()
  const midnight = new Date(now)
  midnight.setHours(0, 0, 0, 0)
  return midnight.getTime() - 60_000
}
const ago = (min: number) => new Date(fixtureNow() - min * 60_000).toISOString()

function items(): ActivityItem[] {
  return [
    {
      kind: 'event',
      id: 'e1',
      at: ago(300),
      actor: { name: 'Trivy', kind: 'system' },
      icon: ArrowRightLeft,
      summary: 'recorded this finding',
    },
    {
      kind: 'event',
      id: 'e2',
      at: ago(290),
      actor: { name: 'System', kind: 'system' },
      icon: ArrowRightLeft,
      summary: 'changed status New → Confirmed',
    },
    {
      kind: 'event',
      id: 'e3',
      at: ago(280),
      actor: { id: 'u-jamie', name: 'Jamie', kind: 'user' },
      icon: ArrowRightLeft,
      summary: 'changed severity High → Critical',
    },
    {
      kind: 'comment',
      id: 'c1',
      commentId: 'cm1',
      at: ago(120),
      actor: { id: 'u-jamie', name: 'Jamie', kind: 'user' },
      body: 'Looks **exploitable** from the edge.',
      reactions: [
        {
          emoji: '👀',
          count: 2,
          reactedByMe: false,
          sampleUsers: [{ name: 'An' }, { name: 'Bo' }],
        },
      ],
    },
    {
      kind: 'comment',
      id: 'c2',
      commentId: 'cm2',
      at: ago(60),
      actor: { id: 'u-me', name: 'Me Myself', kind: 'user' },
      body: 'Patch is in [PR 12](javascript:alert(1)) <img src=x onerror="alert(1)">',
      internal: true,
    },
  ]
}

function setUrl(search: string) {
  window.history.replaceState(null, '', `/findings/f1${search}`)
}

function renderActivity(props: Partial<React.ComponentProps<typeof EntityActivity>> = {}) {
  const onSend = vi.fn().mockResolvedValue(undefined)
  const onToggleReaction = vi.fn().mockResolvedValue(undefined)
  const utils = render(
    <EntityActivity
      entityKey="finding:f1"
      subject="cross-spawn ReDoS"
      items={items()}
      composer={{ onSend, allowInternal: true }}
      onToggleReaction={onToggleReaction}
      shortcut
      {...props}
    />
  )
  return { ...utils, onSend, onToggleReaction }
}

beforeEach(() => {
  setUrl('')
  window.localStorage.clear()
})

describe('ActivityTrigger', () => {
  it('summarises the comments and the latest one as plain text', () => {
    renderActivity()
    const trigger = screen.getByRole('button', { name: /^Activity, 2 comments/ })
    expect(trigger).toHaveTextContent('Activity·2 comments')
    // The latest comment, without markup and without the link target.
    expect(trigger).toHaveTextContent('Me Myself: Patch is in PR 12')
    expect(trigger.textContent).not.toContain('javascript')
  })

  it('shows a "new" dot for items after the last visit, not for your own', () => {
    window.localStorage.setItem(
      'openctem:activity:seen:u-me:finding:f1',
      String(fixtureNow() - 150 * 60_000)
    )
    renderActivity()
    // c1 (Jamie, 2h ago) is new; c2 is mine.
    expect(screen.getByRole('button', { name: /1 new/ })).toBeInTheDocument()
  })
})

describe('ActivityPanel', () => {
  it('opens from the trigger into the URL, closes with Esc and gives focus back', async () => {
    const user = userEvent.setup()
    renderActivity()
    const trigger = screen.getByRole('button', { name: /^Activity, 2 comments/ })
    await user.click(trigger)

    const dialog = await screen.findByRole('dialog', { name: /Activity/ })
    expect(window.location.search).toBe('?activity=open')
    // Focus moved into the panel.
    expect(dialog.contains(document.activeElement)).toBe(true)

    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(window.location.search).toBe('')
    await waitFor(() => expect(trigger).toHaveFocus())
  })

  it('is open on arrival with ?activity=open', async () => {
    setUrl('?activity=open')
    renderActivity()
    expect(await screen.findByRole('dialog', { name: /Activity/ })).toBeInTheDocument()
  })

  it('opens for an old ?tab=activity link and drops the tab parameter', async () => {
    setUrl('?tab=activity&x=1')
    renderActivity()
    expect(await screen.findByRole('dialog', { name: /Activity/ })).toBeInTheDocument()
    expect(window.location.search).toBe('?x=1&activity=open')
  })

  it('keeps the state local in a drawer (no URL parameter)', async () => {
    const user = userEvent.setup()
    renderActivity({ urlParam: false })
    await user.click(screen.getByRole('button', { name: /^Activity, 2 comments/ }))
    expect(await screen.findByRole('dialog', { name: /Activity/ })).toBeInTheDocument()
    expect(window.location.search).toBe('')
  })

  it('opens on Comments, and All folds the run of three changes', async () => {
    const user = userEvent.setup()
    setUrl('?activity=open')
    renderActivity()
    const dialog = await screen.findByRole('dialog', { name: /Activity/ })
    expect(within(dialog).getByRole('radio', { name: 'Comments' })).toHaveAttribute(
      'aria-checked',
      'true'
    )
    expect(within(dialog).getAllByRole('article')).toHaveLength(2)
    expect(within(dialog).queryByText(/changed status/)).not.toBeInTheDocument()

    await user.click(within(dialog).getByRole('radio', { name: 'All' }))
    const folded = within(dialog).getByRole('button', {
      name: '3 changes by Trivy and 2 others. Show them',
    })
    await user.click(folded)
    expect(within(dialog).getByText(/changed status New → Confirmed/)).toBeInTheDocument()
  })

  it('renders comment text sanitised: no raw HTML, no javascript: link', async () => {
    setUrl('?activity=open')
    renderActivity()
    const dialog = await screen.findByRole('dialog', { name: /Activity/ })
    const mine = within(dialog).getByRole('article', { name: 'Comment by Me Myself' })
    expect(mine.querySelector('img[onerror]')).toBeNull()
    const link = within(mine).getByText('PR 12').closest('a')
    expect(link?.getAttribute('href') ?? '').not.toMatch(/javascript/i)
    expect(within(mine).getByText('Internal')).toBeInTheDocument()
  })

  it('sends with Cmd/Ctrl+Enter, shows the comment at once, and retries a failure', async () => {
    const user = userEvent.setup()
    setUrl('?activity=open')
    const onSend = vi.fn().mockRejectedValueOnce(new Error('boom')).mockResolvedValueOnce(undefined)
    renderActivity({ composer: { onSend, allowInternal: true } })
    const dialog = await screen.findByRole('dialog', { name: /Activity/ })
    const box = within(dialog).getByRole('textbox', { name: 'Comment' })
    await user.type(box, 'Fixed in 7.0.5')
    await user.click(within(dialog).getByRole('button', { name: 'Internal' }))
    await user.click(box)
    await user.keyboard('{Control>}{Enter}{/Control}')

    expect(onSend).toHaveBeenCalledWith('Fixed in 7.0.5', { internal: true })
    expect(await within(dialog).findByText('Not sent.')).toBeInTheDocument()
    expect(within(dialog).getByText('Fixed in 7.0.5')).toBeInTheDocument()
    expect(box).toHaveValue('')

    await user.click(within(dialog).getByRole('button', { name: 'Retry' }))
    expect(onSend).toHaveBeenCalledTimes(2)
    await waitFor(() => expect(within(dialog).queryByText('Not sent.')).not.toBeInTheDocument())
  })

  it('keeps an unsent draft when the panel closes', async () => {
    const user = userEvent.setup()
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      renderActivity()
      await user.click(screen.getByRole('button', { name: /^Activity, 2 comments/ }))
      const dialog = await screen.findByRole('dialog', { name: /Activity/ })
      await user.type(within(dialog).getByRole('textbox', { name: 'Comment' }), 'half a thought')
      act(() => void vi.advanceTimersByTime(500))
      await user.keyboard('{Escape}')
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())

      await user.click(screen.getByRole('button', { name: /^Activity, 2 comments/ }))
      const again = await screen.findByRole('dialog', { name: /Activity/ })
      expect(within(again).getByRole('textbox', { name: 'Comment' })).toHaveValue('half a thought')
    } finally {
      vi.useRealTimers()
    }
  })

  it('C opens the panel with the composer focused', async () => {
    const user = userEvent.setup()
    renderActivity()
    await user.keyboard('c')
    const dialog = await screen.findByRole('dialog', { name: /Activity/ })
    await waitFor(() =>
      expect(within(dialog).getByRole('textbox', { name: 'Comment' })).toHaveFocus()
    )
  })

  it('has no composer when read only', async () => {
    setUrl('?activity=open')
    renderActivity({ composer: undefined })
    const dialog = await screen.findByRole('dialog', { name: /Activity/ })
    expect(within(dialog).queryByRole('textbox', { name: 'Comment' })).not.toBeInTheDocument()
  })
})

describe('reactions', () => {
  it('toggles your reaction at once and rolls back when the API refuses', async () => {
    const user = userEvent.setup()
    setUrl('?activity=open')
    const onToggleReaction = vi.fn().mockRejectedValue(new Error('nope'))
    renderActivity({ onToggleReaction })
    const dialog = await screen.findByRole('dialog', { name: /Activity/ })
    const card = within(dialog).getByRole('article', { name: 'Comment by Jamie' })
    const pill = within(card).getByRole('button', { name: '👀 2 reactions, toggle' })
    expect(pill).toHaveAttribute('aria-pressed', 'false')

    await user.click(pill)
    expect(onToggleReaction).toHaveBeenCalledWith(expect.objectContaining({ id: 'c1' }), '👀', true)
    // Optimistic, then rolled back after the rejection.
    await waitFor(() =>
      expect(within(card).getByRole('button', { name: '👀 2 reactions, toggle' })).toHaveAttribute(
        'aria-pressed',
        'false'
      )
    )
  })

  it('adds a quick reaction from the action bar and keeps the pill order', async () => {
    const user = userEvent.setup()
    setUrl('?activity=open')
    let resolve: () => void = () => {}
    const onToggleReaction = vi.fn(() => new Promise<void>((r) => (resolve = r)))
    renderActivity({ onToggleReaction })
    const dialog = await screen.findByRole('dialog', { name: /Activity/ })
    const card = within(dialog).getByRole('article', { name: 'Comment by Jamie' })
    await user.click(within(card).getByRole('button', { name: 'React with 👍' }))

    const pills = within(within(card).getByRole('group', { name: 'Reactions' })).getAllByRole(
      'button',
      { pressed: undefined }
    )
    expect(pills.map((p) => p.getAttribute('aria-label'))).toEqual([
      '👀 2 reactions, toggle',
      '👍 1 reaction, including you, toggle',
      'Add reaction',
    ])
    act(() => resolve())
  })
})
