import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { WatchersControl } from '../watchers-control'
import { UNDO_TOAST_MS } from '../use-watcher-actions'
import type { Participants } from '../../../api/use-participants'
import en from '@/lib/i18n/dictionaries/en/findings.json'
import vi_ from '@/lib/i18n/dictionaries/vi/findings.json'

const setWatching = vi.fn()
const addWatchers = vi.fn()
const removeWatcher = vi.fn()
let participants: Participants | undefined
vi.mock('../../../api/use-participants', async () => {
  const actual = await vi.importActual<typeof import('../../../api/use-participants')>(
    '../../../api/use-participants'
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

const toastSuccess = vi.fn()
vi.mock('sonner', () => ({ toast: { success: (...a: unknown[]) => toastSuccess(...a) } }))

// The English dictionary, so the test also proves every key exists.
const dict = en as Record<string, string>
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    t: (k: string, fallback?: string, vars?: Record<string, unknown>) =>
      (dict[k] ?? `MISSING:${k}:${fallback}`).replace(/\{(\w+)\}/g, (_m, v) =>
        String(vars?.[v] ?? '')
      ),
  }),
}))

const base: Participants = {
  watcher_count: 3,
  names_visible: true,
  watchers: [
    {
      user_id: 'u-lan',
      name: 'Lan Anh',
      reason: 'added',
      added_by: 'u-admin',
      added_by_name: 'Admin User',
      since: '2026-10-20T00:00:00Z',
    },
    { user_id: 'u-me', name: 'Minh Nguyen', reason: 'assigned', since: '2026-10-20T00:00:00Z' },
    {
      user_id: 'u-thu',
      name: 'Thu Ha',
      reason: 'added',
      added_by: 'u-me',
      since: '2026-10-20T00:00:00Z',
    },
  ],
  asset_owners: [{ user_id: 'u-admin', name: 'Admin User', type: 'primary' }],
  me: { user_id: 'u-me', state: 'subscribed', reason: 'assigned' },
}

const picker = {
  candidates: [
    { id: 'u-lan', name: 'Lan Anh' }, // already watching: not offered
    { id: 'u-new', name: 'New Person' },
  ],
  isLoading: false,
  onSearch: vi.fn(),
  onOpenChange: vi.fn(),
}

function renderControl(
  props: Partial<React.ComponentProps<typeof WatchersControl>> = {}
): ReturnType<typeof render> {
  return render(
    <dl>
      <WatchersControl
        kind="finding"
        itemId="f-1"
        canAdd
        canRemoveOthers
        picker={picker}
        {...props}
      />
    </dl>
  )
}

async function openSheet() {
  await userEvent.click(screen.getByRole('button', { name: /watching, manage watchers/i }))
  return screen.getByRole('dialog')
}

beforeEach(() => {
  setWatching.mockReset().mockResolvedValue(true)
  addWatchers.mockReset().mockResolvedValue(true)
  removeWatcher.mockReset().mockResolvedValue(true)
  toastSuccess.mockReset()
  picker.onOpenChange.mockReset()
  participants = base
})

describe('WatchersControl rail rows', () => {
  it('summarises watchers in one row and has no control that removes anyone', () => {
    renderControl()
    expect(screen.getByText('3 watching')).toBeInTheDocument()
    expect(screen.getByText('Admin User')).toBeInTheDocument() // asset owner context
    expect(screen.queryByRole('button', { name: /remove/i })).not.toBeInTheDocument()
    // Names are in the sheet, not listed in the rail.
    expect(screen.queryByText('Lan Anh')).not.toBeInTheDocument()
  })

  it('the self toggle names the action and offers Undo in its toast', async () => {
    renderControl()
    const toggle = screen.getByRole('button', { name: 'Stop watching this finding' })
    expect(toggle).toHaveTextContent('Watching')
    await userEvent.click(toggle)
    expect(setWatching).toHaveBeenCalledWith(false)
    const [message, opts] = toastSuccess.mock.calls[0]
    expect(message).toBe('You stopped watching this finding')
    expect(opts.duration).toBe(UNDO_TOAST_MS)
    expect(UNDO_TOAST_MS).toBeGreaterThanOrEqual(8000)
    opts.action.onClick()
    expect(setWatching).toHaveBeenLastCalledWith(true)
  })

  it('says Watch when you are not watching', () => {
    participants = { ...base, me: { user_id: 'u-me', state: 'unsubscribed' } }
    renderControl({ kind: 'task' })
    expect(screen.getByRole('button', { name: 'Watch this task' })).toHaveTextContent('Watch')
  })

  it('shows only the count when the API hides names', async () => {
    participants = { ...base, names_visible: false, watchers: [], asset_owners: [] }
    renderControl()
    expect(screen.getByText('3 watching')).toBeInTheDocument()
    const sheet = await openSheet()
    expect(within(sheet).getByText(en['findings.people.namesHidden'])).toBeInTheDocument()
    expect(within(sheet).queryByRole('list', { name: 'Watchers' })).not.toBeInTheDocument()
  })
})

describe('Manage watchers sheet', () => {
  it('lists you first, with the reason each person watches', async () => {
    renderControl()
    const sheet = await openSheet()
    const rows = within(within(sheet).getByRole('list', { name: 'Watchers' })).getAllByRole(
      'listitem'
    )
    expect(rows[0]).toHaveTextContent('Minh Nguyen(you)')
    expect(rows[0]).toHaveTextContent('Was assigned')
    expect(rows[1]).toHaveTextContent('Added by Admin User')
    expect(rows[2]).toHaveTextContent('Added by you')
  })

  it('your own row stops watching (sticky), it never deletes your row', async () => {
    renderControl()
    const sheet = await openSheet()
    expect(within(sheet).queryByRole('button', { name: 'Remove Minh Nguyen' })).toBeNull()
    await userEvent.click(within(sheet).getByRole('button', { name: 'Stop watching' }))
    expect(setWatching).toHaveBeenCalledWith(false)
    expect(removeWatcher).not.toHaveBeenCalled()
  })

  it('removes someone at once and Undo adds them back', async () => {
    renderControl()
    const sheet = await openSheet()
    await userEvent.click(within(sheet).getByRole('button', { name: 'Remove Lan Anh' }))
    expect(removeWatcher).toHaveBeenCalledWith('u-lan')
    const [message, opts] = toastSuccess.mock.calls[0]
    expect(message).toBe('Lan Anh removed from watchers')
    expect(opts.action.label).toBe('Undo')
    expect(opts.duration).toBe(UNDO_TOAST_MS)
    await opts.action.onClick()
    expect(addWatchers).toHaveBeenCalledWith(['u-lan'])
    expect(toastSuccess).toHaveBeenLastCalledWith('Lan Anh is watching again')
  })

  it('offers no Undo when the removal failed', async () => {
    removeWatcher.mockResolvedValue(false)
    renderControl()
    const sheet = await openSheet()
    await userEvent.click(within(sheet).getByRole('button', { name: 'Remove Lan Anh' }))
    expect(toastSuccess).not.toHaveBeenCalled()
  })

  it('without the permission to remove others, offers no Remove at all', async () => {
    renderControl({ canRemoveOthers: false, canAdd: false })
    const sheet = await openSheet()
    expect(within(sheet).queryByRole('button', { name: /^remove/i })).toBeNull()
    expect(within(sheet).queryByText('Add people')).toBeNull()
  })

  it('adds people who are not watching yet, loading candidates on open', async () => {
    renderControl()
    const sheet = await openSheet()
    expect(picker.onOpenChange).toHaveBeenCalledWith(true)
    const candidates = within(sheet).getByRole('list', { name: 'People you can add' })
    expect(within(candidates).queryByText('Lan Anh')).toBeNull()
    await userEvent.click(within(sheet).getByRole('button', { name: 'Add New Person' }))
    expect(addWatchers).toHaveBeenCalledWith(['u-new'])
    expect(within(sheet).getByText(en['findings.people.onlyReaders'])).toBeInTheDocument()
  })

  it('a task says people who cannot open it cannot be added', async () => {
    renderControl({ kind: 'task' })
    const sheet = await openSheet()
    expect(within(sheet).queryByText(en['findings.people.onlyReaders'])).toBeNull()
    expect(within(sheet).getByText(en['findings.people.taskCandidatesHint'])).toBeInTheDocument()
  })

  it('offers Watch inside the sheet when you are not watching', async () => {
    participants = {
      ...base,
      watchers: base.watchers.filter((w) => w.user_id !== 'u-me'),
      me: { user_id: 'u-me', state: 'unsubscribed' },
    }
    renderControl()
    const sheet = await openSheet()
    await userEvent.click(within(sheet).getByRole('button', { name: 'Watch' }))
    expect(setWatching).toHaveBeenCalledWith(true)
  })
})

describe('watchers i18n', () => {
  it('has every people key in Vietnamese too', () => {
    const viDict = vi_ as Record<string, string>
    const missing = Object.keys(dict)
      .filter((k) => k.startsWith('findings.people.'))
      .filter((k) => !viDict[k])
    expect(missing).toEqual([])
  })
})
