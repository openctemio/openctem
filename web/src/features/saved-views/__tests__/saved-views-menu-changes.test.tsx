import axe from 'axe-core'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { SavedViewsMenu, summarizeChanges } from '../components/saved-views-menu'
import { createSavedView, updateSavedView, type SavedView } from '../api/use-saved-views'
import type { ViewChange } from '../lib/view-changes'

const V1 = '019feab9-1111-7222-8333-444455556661'
const V2 = '019feab9-1111-7222-8333-444455556662'
const mine = {
  id: V1,
  name: 'Crown jewels',
  description: 'My crown jewels',
  is_owner: true,
  group_id: undefined,
  group_name: '',
  filter: { v: 1 },
} as unknown as SavedView
const theirs = { ...mine, id: V2, name: 'Team view', is_owner: false } as SavedView

const state: { views: SavedView[] } = { views: [mine, theirs] }
vi.mock('../api/use-saved-views', async (orig) => ({
  ...(await orig<typeof import('../api/use-saved-views')>()),
  useSavedViews: () => ({ views: state.views, mutate: vi.fn() }),
  createSavedView: vi.fn((i: { name: string }) =>
    Promise.resolve({ ...mine, id: 'new', name: i.name })
  ),
  updateSavedView: vi.fn((_id: string, i: { name: string }) =>
    Promise.resolve({ ...mine, name: i.name })
  ),
}))
vi.mock('@/features/access-control/api/use-groups', () => ({
  useMyGroups: () => ({ groups: [{ id: 'g1', name: 'Platform team' }] }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

Element.prototype.scrollIntoView ??= () => {}
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const changed: ViewChange[] = [{ kind: 'filters', count: 2 }, { kind: 'columns' }]

function menu(props: Partial<React.ComponentProps<typeof SavedViewsMenu>> = {}) {
  const onSelect = vi.fn()
  const onDiscard = vi.fn()
  const view = render(
    <SavedViewsMenu
      page="findings"
      activeId={V1}
      changes={changed}
      columns={['title', 'priorityClass', 'asset']}
      density="compact"
      groupBy="cve_id"
      onSelect={onSelect}
      onDiscard={onDiscard}
      {...props}
    />
  )
  return { onSelect, onDiscard, ...view }
}

beforeEach(() => {
  state.views = [mine, theirs]
  vi.mocked(createSavedView).mockClear()
  vi.mocked(updateSavedView).mockClear()
  window.history.replaceState(null, '', `/findings?view=${V1}&epss_score_gte=0.5&columns=asset`)
})

describe('unsaved-changes dot', () => {
  it('shows a dot, and says so in the button name, when the list differs from the view', () => {
    menu()
    expect(screen.getByTestId('saved-view-dirty-dot')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Crown jewels, unsaved changes' })).toHaveAttribute(
      'data-dirty',
      'true'
    )
  })

  it('shows none when nothing changed', () => {
    menu({ changes: [] })
    expect(screen.queryByTestId('saved-view-dirty-dot')).toBeNull()
    expect(screen.getByRole('button', { name: 'Crown jewels' })).not.toHaveAttribute('data-dirty')
  })

  it('shows none without an open view', () => {
    menu({ activeId: undefined })
    expect(screen.queryByTestId('saved-view-dirty-dot')).toBeNull()
  })

  it('falls back to the modified flag when no change list is given', () => {
    menu({ changes: undefined, modified: true })
    expect(screen.getByTestId('saved-view-dirty-dot')).toBeInTheDocument()
  })
})

describe('summarizeChanges', () => {
  const t = (key: string, fallback?: string, vars?: Record<string, string | number>) =>
    (fallback ?? key).replace(
      '{count, plural, one {# filter added} other {# filters added}}',
      `${vars?.count} filter${vars?.count === 1 ? '' : 's'} added`
    )
  it('names each kind', () => {
    expect(
      summarizeChanges(
        [
          { kind: 'filters', count: 1 },
          { kind: 'search' },
          { kind: 'sort' },
          { kind: 'group' },
          { kind: 'columns' },
          { kind: 'density' },
        ],
        t
      )
    ).toBe(
      '1 filter added, search changed, sort changed, grouping changed, columns changed, density changed'
    )
  })
})

describe('the menu of a view with unsaved changes', () => {
  it('says what changed and offers Save changes, Save as new view and Discard', async () => {
    const { onDiscard } = menu()
    await userEvent.click(screen.getByRole('button', { name: /unsaved changes/ }))
    expect(await screen.findByText(/^Unsaved changes to /)).toHaveTextContent(
      'Unsaved changes to “Crown jewels”: 2 filters added, columns changed'
    )
    expect(screen.getByRole('menuitem', { name: 'Save changes' })).toBeInTheDocument()
    expect(screen.getByRole('menuitem', { name: 'Save as new view…' })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('menuitem', { name: 'Discard changes' }))
    expect(onDiscard).toHaveBeenCalled()
  })

  it('Save changes updates the open view with its columns, density and the URL on top', async () => {
    const { onDiscard } = menu()
    await userEvent.click(screen.getByRole('button', { name: /unsaved changes/ }))
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Save changes' }))
    await waitFor(() => expect(updateSavedView).toHaveBeenCalled())
    const [id, body] = vi.mocked(updateSavedView).mock.calls[0]
    expect(id).toBe(V1)
    expect(body).toMatchObject({
      page: 'findings',
      name: 'Crown jewels',
      columns: ['title', 'priorityClass', 'asset'],
      density: 'compact',
      group_by: 'cve_id',
    })
    // The open view stays in the query (the API saves its filter with these on top);
    // page-only params do not travel.
    const q = new URLSearchParams(body.query)
    expect(q.get('view')).toBe(V1)
    expect(q.get('epss_score_gte')).toBe('0.5')
    expect(q.has('columns')).toBe(false)
    await waitFor(() => expect(onDiscard).toHaveBeenCalled())
  })

  it('a view someone else owns can only be saved as a new one', async () => {
    state.views = [theirs]
    menu({ activeId: V2 })
    await userEvent.click(screen.getByRole('button', { name: /unsaved changes/ }))
    expect(screen.queryByRole('menuitem', { name: 'Save changes' })).toBeNull()
    expect(await screen.findByRole('menuitem', { name: 'Save as new view…' })).toBeInTheDocument()
  })

  it('Save as new view creates a view with the columns and density', async () => {
    const { onSelect } = menu()
    await userEvent.click(screen.getByRole('button', { name: /unsaved changes/ }))
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Save as new view…' }))
    await userEvent.type(await screen.findByLabelText('Name'), 'Triage layout')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(createSavedView).toHaveBeenCalled())
    expect(vi.mocked(createSavedView).mock.calls[0][0]).toMatchObject({
      name: 'Triage layout',
      columns: ['title', 'priorityClass', 'asset'],
      density: 'compact',
      group_by: 'cve_id',
    })
    await waitFor(() => expect(onSelect).toHaveBeenCalled())
  })

  it('has no accessibility violations with the menu open', async () => {
    menu()
    await userEvent.click(screen.getByRole('button', { name: /unsaved changes/ }))
    await screen.findByText(/^Unsaved changes to /)
    const res = await axe.run(document.body, {
      rules: { 'color-contrast': { enabled: false }, region: { enabled: false } },
    })
    expect(res.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' '))}`)).toEqual(
      []
    )
  })
})

describe('sharing', () => {
  async function openSave() {
    menu({ activeId: undefined, changes: undefined })
    await userEvent.click(screen.getByRole('button', { name: 'Views' }))
    await userEvent.click(await screen.findByRole('menuitem', { name: /save current filters/i }))
    await userEvent.click(await screen.findByRole('combobox', { name: 'Visible to' }))
  }

  // Organization-wide views wait for the API that stores them; until then the
  // menu offers only the viewer and their groups, and sends no org field.
  it('offers only me and my groups, never the whole organization', async () => {
    await openSave()
    expect(await screen.findByRole('option', { name: 'Only me' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Platform team' })).toBeInTheDocument()
    expect(screen.queryByRole('option', { name: /organization/i })).toBeNull()
  })

  it('a saved view carries a query, never rows or an org flag', async () => {
    await openSave()
    await userEvent.click(await screen.findByRole('option', { name: 'Platform team' }))
    await userEvent.type(screen.getByLabelText('Name'), 'Team view')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(createSavedView).toHaveBeenCalled())
    const body = vi.mocked(createSavedView).mock.calls[0][0] as unknown as Record<string, unknown>
    expect(body.group_id).toBe('g1')
    expect(typeof body.query).toBe('string')
    expect(Object.keys(body).sort()).toEqual(expect.arrayContaining(['name', 'page', 'query']))
    for (const k of Object.keys(body)) {
      expect(['page', 'name', 'query', 'group_id', 'group_by', 'columns', 'density']).toContain(k)
    }
  })
})
