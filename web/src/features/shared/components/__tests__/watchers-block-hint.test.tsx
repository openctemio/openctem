import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { WatchersBlock } from '../watchers-block'
import en from '@/lib/i18n/dictionaries/en/findings.json'

vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({ t: (k: string) => (en as Record<string, string>)[k] ?? k }),
}))
vi.mock('../../api/use-participants', () => ({
  useParticipants: () => ({
    participants: { me: { state: 'none' }, watchers: [], watcher_count: 0 },
    isLoading: false,
    busy: false,
    setWatching: vi.fn(),
    addWatchers: vi.fn(),
    removeWatcher: vi.fn(),
  }),
}))
vi.mock('../watch-toggle', () => ({ WatchToggle: () => null }))

// cmdk measures its list with ResizeObserver, which jsdom lacks.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}
Element.prototype.scrollIntoView ??= () => {}

const picker = { candidates: [], isLoading: false, onSearch: vi.fn(), onOpenChange: vi.fn() }

function open(kind: 'finding' | 'task') {
  render(<WatchersBlock kind={kind} itemId="x" canAdd canRemoveOthers picker={picker} />)
  fireEvent.click(screen.getByRole('button', { name: /add/i }))
}

describe('watcher picker hint', () => {
  it('says only readers are listed for a finding', () => {
    open('finding')
    expect(screen.getByText(en['findings.people.onlyReaders'])).toBeTruthy()
  })
  it('does not claim that for a task', () => {
    open('task')
    expect(screen.queryByText(en['findings.people.onlyReaders'])).toBeNull()
    expect(screen.getByText(en['findings.people.taskCandidatesHint'])).toBeTruthy()
  })
})
