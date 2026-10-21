import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { WatchersBlock } from '../watchers-block'
import type { Participants } from '../../api/use-participants'

const setWatching = vi.fn()
const addWatchers = vi.fn()
const removeWatcher = vi.fn()
let participants: Participants | undefined
vi.mock('../../api/use-participants', async () => {
  const actual = await vi.importActual<typeof import('../../api/use-participants')>(
    '../../api/use-participants'
  )
  return {
    ...actual,
    useParticipants: () => ({
      participants,
      isLoading: false,
      busy: false,
      setWatching,
      addWatchers,
      removeWatcher,
    }),
  }
})
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    t: (_k: string, fallback?: string, vars?: Record<string, unknown>) =>
      (fallback ?? _k).replace(/\{(\w+)\}/g, (_m, k) => String(vars?.[k] ?? '')),
  }),
}))

const base: Participants = {
  watcher_count: 2,
  names_visible: true,
  watchers: [
    { user_id: 'u-lan', name: 'Lan Anh', reason: 'commented', since: '2026-10-20T00:00:00Z' },
    { user_id: 'u-quang', name: 'Quang B', reason: 'added', since: '2026-10-20T00:00:00Z' },
  ],
  asset_owners: [{ user_id: 'u-hoa', name: 'Hoa V', type: 'primary' }],
  me: { state: 'subscribed', reason: 'manual' },
}

beforeEach(() => {
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    }
  )
  Element.prototype.scrollIntoView = vi.fn()
  setWatching.mockReset()
  addWatchers.mockReset()
  removeWatcher.mockReset()
  participants = base
})

describe('WatchersBlock', () => {
  it('lists watchers with the reason each one watches, and the asset owners', () => {
    render(<WatchersBlock kind="finding" itemId="f-1" canAdd={false} canRemoveOthers={false} />)
    expect(screen.getByText('Lan Anh')).toBeInTheDocument()
    expect(screen.getByText('commented')).toBeInTheDocument()
    expect(screen.getByText('added')).toBeInTheDocument()
    expect(screen.getByText('Hoa V')).toBeInTheDocument()
    expect(screen.getByText('primary')).toBeInTheDocument()
  })

  it('shows only the count, no names, when the API hides them', () => {
    participants = {
      ...base,
      names_visible: false,
      watchers: [],
      asset_owners: [],
      watcher_count: 4,
    }
    render(<WatchersBlock kind="finding" itemId="f-1" canAdd={false} canRemoveOthers={false} />)
    expect(screen.queryByText('Lan Anh')).not.toBeInTheDocument()
    expect(screen.getByText('4')).toBeInTheDocument()
    expect(screen.getByText(/shown to people who can see the member list/i)).toBeInTheDocument()
    // The bell still works for a viewer.
    expect(screen.getByRole('button', { name: /watching/i })).toBeInTheDocument()
  })

  it('hides the add control without permission and offers it with one', () => {
    const picker = {
      candidates: [{ id: 'u-new', name: 'New Person' }],
      isLoading: false,
      onSearch: vi.fn(),
      onOpenChange: vi.fn(),
    }
    const { rerender } = render(
      <WatchersBlock
        kind="finding"
        itemId="f-1"
        canAdd={false}
        canRemoveOthers={false}
        picker={picker}
      />
    )
    expect(screen.queryByRole('button', { name: 'Add' })).not.toBeInTheDocument()
    rerender(
      <WatchersBlock kind="finding" itemId="f-1" canAdd canRemoveOthers={false} picker={picker} />
    )
    expect(screen.getByRole('button', { name: 'Add' })).toBeInTheDocument()
  })

  it('adds the chosen person and tells the caller the picker opened', async () => {
    addWatchers.mockResolvedValue(true)
    const picker = {
      candidates: [
        { id: 'u-lan', name: 'Lan Anh' }, // already watching: not offered
        { id: 'u-new', name: 'New Person' },
      ],
      isLoading: false,
      onSearch: vi.fn(),
      onOpenChange: vi.fn(),
    }
    render(
      <WatchersBlock kind="finding" itemId="f-1" canAdd canRemoveOthers={false} picker={picker} />
    )
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))
    expect(picker.onOpenChange).toHaveBeenCalledWith(true)
    expect(screen.getAllByText('Lan Anh')).toHaveLength(1) // only the watcher row
    await userEvent.click(screen.getByText('New Person'))
    expect(addWatchers).toHaveBeenCalledWith(['u-new'])
  })

  it('lets you remove yourself, and others only with permission', () => {
    const { rerender } = render(
      <WatchersBlock
        kind="finding"
        itemId="f-1"
        canAdd={false}
        canRemoveOthers={false}
        currentUserId="u-lan"
      />
    )
    expect(screen.getByRole('button', { name: 'Remove Lan Anh' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Remove Quang B' })).not.toBeInTheDocument()
    rerender(
      <WatchersBlock
        kind="finding"
        itemId="f-1"
        canAdd={false}
        canRemoveOthers
        currentUserId="u-lan"
      />
    )
    expect(screen.getByRole('button', { name: 'Remove Quang B' })).toBeInTheDocument()
  })

  it('removes a watcher on click', async () => {
    removeWatcher.mockResolvedValue(true)
    render(
      <WatchersBlock kind="task" itemId="t-1" canAdd={false} canRemoveOthers currentUserId="x" />
    )
    await userEvent.click(screen.getByRole('button', { name: 'Remove Quang B' }))
    expect(removeWatcher).toHaveBeenCalledWith('u-quang')
  })

  it('toggles the bell and says what pressing does', async () => {
    render(<WatchersBlock kind="task" itemId="t-1" canAdd={false} canRemoveOthers={false} />)
    const bell = screen.getByRole('button', { name: 'Watching' })
    expect(bell).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByText('You get updates on this task.')).toBeInTheDocument()
    await userEvent.click(bell)
    expect(setWatching).toHaveBeenCalledWith(false)
  })

  it('offers to start watching when you are not', () => {
    participants = { ...base, me: { state: 'unsubscribed' } }
    render(<WatchersBlock kind="finding" itemId="f-1" canAdd={false} canRemoveOthers={false} />)
    const bell = screen.getByRole('button', { name: 'Not watching' })
    expect(bell).toHaveAttribute('aria-pressed', 'false')
    expect(screen.getByText('Watch it to get updates on this finding.')).toBeInTheDocument()
  })
})
