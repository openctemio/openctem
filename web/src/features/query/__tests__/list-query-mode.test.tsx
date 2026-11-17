import { describe, expect, it, vi, beforeEach } from 'vitest'
import { act, fireEvent, render, screen } from '@testing-library/react'
import { useState } from 'react'
import { ListSearch } from '@/features/shared/components/list-search'
import { ListToolbar } from '@/features/shared/components/list-toolbar'
import { FilterChipsRow, LockedChip } from '@/features/shared/components/filter-chips-row'
import {
  joinFilterText,
  joinViewText,
  modePageParams,
  queryModeIn,
  useListQueryMode,
  viewOpensInQueryMode,
  withQueryMode,
} from '../components/query-mode'
import type { ParseRequest, ParseResult } from '../api/query-api'

const api = vi.hoisted(() => ({ parse: vi.fn(), values: vi.fn() }))
vi.mock('../api/query-api', () => ({
  queryApi: api,
  useQuerySchema: () => ({ data: { fields: [] } }),
}))

function result(over: Partial<ParseResult> = {}): ParseResult {
  return {
    entity: 'findings',
    valid: true,
    text: '',
    query: '',
    chips: [],
    advanced: false,
    problems: [],
    ...over,
  }
}

// Answers of POST /query/parse recorded from the server (findings entity).
const PRINTED = result({
  text: 'practice!=compliance severity=critical state=open',
  params: { practice_not: 'compliance', severity: 'critical', state: 'open' },
})
const KEV = result({ text: 'is_in_kev=true', params: { is_in_kev: 'true' } })
const REFUSED = result({
  valid: false,
  problems: [
    {
      code: 'unknown_value',
      message: 'must be one of: critical, high, medium, low, info, none',
      start: 10,
      end: 13,
      line: 1,
      column: 11,
    },
  ],
})

/**
 * The server: params print as PRINTED; a filter document prints the text its
 * `text` key names (a stand-in for the printer); texts answer from a table.
 */
function serve(texts: Record<string, ParseResult>) {
  api.parse.mockImplementation((req: ParseRequest) =>
    Promise.resolve(
      req.document !== undefined
        ? result({ text: String(req.document.text) })
        : req.params !== undefined
          ? PRINTED
          : (texts[req.text ?? ''] ?? REFUSED)
    )
  )
}

function Harness({
  onApply,
  fq = null,
  initialActive = false,
  params = 'severity=critical&state=open&practice_not=compliance',
  base,
}: {
  onApply: (r: ParseResult) => void
  fq?: string | null
  /** The page URL says Query mode (a link, a reload). */
  initialActive?: boolean
  params?: string
  /** The open saved view's filter document. */
  base?: Record<string, unknown> | null
}) {
  // The page keeps the mode in its URL; here, in state.
  const [active, setActive] = useState(initialActive)
  const mode = useListQueryMode({
    entity: 'findings',
    active,
    onActiveChange: setActive,
    fq,
    params,
    base,
    onApply: (r, on) => {
      onApply(r)
      setActive(on)
    },
    testId: 'q-editor',
  })
  return (
    <ListSearch
      value=""
      onChange={() => undefined}
      placeholder="Search findings"
      query={mode.query}
    />
  )
}

/** The field in a list toolbar, as the findings, assets and scans lists draw it. */
function ToolbarHarness({ context = false }: { context?: boolean }) {
  const [active, setActive] = useState(true)
  const mode = useListQueryMode({
    entity: 'findings',
    active,
    onActiveChange: setActive,
    fq: null,
    params: 'severity=critical&state=open&practice_not=compliance',
    onApply: (_r, on) => setActive(on),
    testId: 'q-editor',
  })
  return (
    <ListToolbar
      search={{
        value: '',
        onChange: () => undefined,
        placeholder: 'Search findings',
        query: mode.query,
      }}
      start={<button type="button">State: Open</button>}
      end={<button type="button">Views</button>}
      below={
        context ? (
          <FilterChipsRow leading={<LockedChip>Asset: web-01</LockedChip>} chips={[]} />
        ) : undefined
      }
    />
  )
}

const UNKNOWN_FIELD = result({
  valid: false,
  problems: [
    {
      code: 'unknown_field',
      message: 'unknown field "severty" on findings',
      start: 0,
      end: 7,
      line: 1,
      column: 1,
      suggestions: ['severity'],
    },
  ],
})

async function settle() {
  // The editor loads on use (a lazy chunk).
  await act(async () => {
    await vi.dynamicImportSettled()
    await vi.advanceTimersByTimeAsync(400)
  })
}

const box = () => screen.getByRole('combobox') as HTMLInputElement
const basic = () => screen.getByRole('button', { name: 'Basic' })
const query = () => screen.getByRole('button', { name: 'Query' })

describe('the list search field Query mode', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    api.parse.mockReset()
    api.values.mockReset()
    api.values.mockReturnValue(new Promise(() => {}))
    window.localStorage.clear()
  })

  it('Basic to Query shows the filter printed by the server from the page params', async () => {
    serve({})
    render(<Harness onApply={vi.fn()} />)
    expect(basic()).toHaveAttribute('aria-pressed', 'true')
    fireEvent.click(query())
    await settle()
    expect(api.parse).toHaveBeenCalledWith({
      entity: 'findings',
      params: 'severity=critical&state=open&practice_not=compliance',
    })
    expect(box().value).toBe('practice!=compliance severity=critical state=open')
    expect(query()).toHaveAttribute('aria-pressed', 'true')
  })

  it('round trip: back to Basic without an edit applies nothing', async () => {
    serve({})
    const onApply = vi.fn()
    render(<Harness onApply={onApply} />)
    fireEvent.click(query())
    await settle()
    fireEvent.click(basic())
    await settle()
    expect(onApply).not.toHaveBeenCalled()
    expect(basic()).toHaveAttribute('aria-pressed', 'true')
    expect(screen.queryByRole('combobox')).toBeNull()
  })

  it('Enter applies a valid text and stays in Query mode', async () => {
    serve({ 'kev=true': KEV })
    const onApply = vi.fn()
    render(<Harness onApply={onApply} />)
    fireEvent.click(query())
    await settle()
    fireEvent.change(box(), { target: { value: 'kev=true' } })
    fireEvent.keyDown(box(), { key: 'Enter' })
    await settle()
    expect(onApply).toHaveBeenCalledWith(KEV)
    expect(query()).toHaveAttribute('aria-pressed', 'true')
  })

  it('Enter on the text already in force writes nothing (an open saved view keeps its own scope)', async () => {
    serve({ [PRINTED.text]: PRINTED })
    const onApply = vi.fn()
    render(<Harness onApply={onApply} />)
    fireEvent.click(query())
    await settle()
    expect(box().value).toBe(PRINTED.text)
    fireEvent.keyDown(box(), { key: 'Enter' })
    await settle()
    expect(onApply).not.toHaveBeenCalled()
    expect(query()).toHaveAttribute('aria-pressed', 'true')
  })

  it('Query to Basic applies an edit not applied yet, so the switch drops nothing', async () => {
    serve({ 'kev=true': KEV })
    const onApply = vi.fn()
    render(<Harness onApply={onApply} />)
    fireEvent.click(query())
    await settle()
    fireEvent.change(box(), { target: { value: 'kev=true' } })
    fireEvent.click(basic())
    await settle()
    expect(onApply).toHaveBeenCalledWith(KEV)
    expect(basic()).toHaveAttribute('aria-pressed', 'true')
  })

  it('a text the parser refuses is never applied: inline problem with its column, field on the error', async () => {
    serve({})
    const onApply = vi.fn()
    render(<Harness onApply={onApply} />)
    fireEvent.click(query())
    await settle()
    fireEvent.change(box(), { target: { value: 'severity= AND kev=true' } })
    fireEvent.keyDown(box(), { key: 'Enter' })
    await settle()
    expect(onApply).not.toHaveBeenCalled()
    expect(box()).toHaveAttribute('aria-invalid', 'true')
    expect(screen.getByText(/Column 11\./)).toBeTruthy()
    // The field selects the problem, so it scrolls there.
    expect(box().selectionStart).toBe(10)
    expect(box().selectionEnd).toBe(13)
    // Switching to Basic keeps Query mode and the text.
    fireEvent.click(basic())
    await settle()
    expect(onApply).not.toHaveBeenCalled()
    expect(query()).toHaveAttribute('aria-pressed', 'true')
    expect(box().value).toBe('severity= AND kev=true')
  })

  it('in a toolbar the problem line is drawn in the status row under the toolbar, never in the toolbar row', async () => {
    serve({ 'severty=high': UNKNOWN_FIELD, 'severity=high': KEV })
    const { container } = render(<ToolbarHarness />)
    await settle()
    const toolbar = container.querySelector('[data-slot="list-toolbar"]')!
    const status = container.querySelector('[data-slot="list-toolbar-status"]')!
    // At rest the row draws no box (no gap, no height); the line in it is
    // the field's live description, read out and not shown.
    expect(status).not.toHaveAttribute('data-drawn')
    expect(status.className).toBe('contents')
    const line = () => document.getElementById(box().getAttribute('aria-describedby')!)!
    expect(status.contains(line())).toBe(true)
    expect(toolbar.contains(line())).toBe(false)
    expect(line()).toHaveAttribute('aria-live', 'polite')
    expect(line()).toHaveClass('sr-only')
    const atRest = line()

    fireEvent.change(box(), { target: { value: 'severty=high' } })
    fireEvent.keyDown(box(), { key: 'Enter' })
    await settle()
    // The problem: one line of the chips row's height under the toolbar.
    expect(status).toHaveAttribute('data-drawn', '')
    // A row of its own under the toolbar (after line 2 on a phone).
    expect(status).toHaveClass(
      'h-control',
      'max-md:h-control-touch',
      'basis-full',
      '@max-md/toolbar:order-last'
    )
    expect(box()).toHaveAttribute('aria-invalid', 'true')
    // The same live region as before, so the problem is announced.
    expect(line()).toBe(atRest)
    expect(line()).not.toHaveClass('sr-only')
    expect(line()).toHaveAttribute('data-drawn', '')
    expect(toolbar.querySelector('[data-slot="query-status"]')).toBeNull()
    // Long problems are cut on that one line, in full in the title.
    const text = screen.getByText(/Unknown field\. Column 1\./)
    expect(text).toHaveClass('truncate')
    expect(text).toHaveAttribute('title', 'Unknown field. Column 1.')
    expect(text.parentElement).toHaveClass('flex-nowrap')
    // The fix stays a button that keeps its size, and it works.
    const fix = screen.getByRole('button', { name: 'severity' })
    expect(status.contains(fix)).toBe(true)
    expect(fix).toHaveClass('shrink-0')
    fireEvent.click(fix)
    await settle()
    expect(box().value).toBe('severity=high')
    expect(status).not.toHaveAttribute('data-drawn')
    expect(status.className).toBe('contents')
    expect(box()).toHaveAttribute('aria-invalid', 'false')
  })

  it('beside a context chip row the problem shares that row; leaving Query mode takes the status row away', async () => {
    serve({ 'severty=high': UNKNOWN_FIELD })
    const { container } = render(<ToolbarHarness context />)
    await settle()
    const below = container.querySelector('[data-slot="list-toolbar-below"]')!
    const status = container.querySelector('[data-slot="list-toolbar-status"]')!
    expect(below.className).not.toContain('@md/toolbar:flex-[0_0_auto]')
    fireEvent.change(box(), { target: { value: 'severty=high' } })
    fireEvent.keyDown(box(), { key: 'Enter' })
    await settle()
    // The chips row gives the rest of its line to the problem (same line,
    // so the list does not move); a phone gives the problem the last line.
    expect(status).toHaveAttribute('data-drawn', '')
    expect(status).toHaveClass(
      'h-control',
      'flex-[1_1_0%]',
      '@max-md/toolbar:order-last',
      '@max-md/toolbar:flex-[0_0_100%]'
    )
    expect(below).toHaveClass('@md/toolbar:flex-[0_0_auto]', '@md/toolbar:max-w-[50%]')
    expect(below.nextElementSibling).toBe(status)
    // A local problem (a quote left open) is drawn there too once refused.
    fireEvent.change(box(), { target: { value: 'title="abc' } })
    fireEvent.keyDown(box(), { key: 'Enter' })
    await settle()
    expect(status).toHaveAttribute('data-drawn', '')
    expect(status.querySelector('.truncate')).toHaveAttribute('title')
    // Escape puts the applied text back: no problem, no row.
    fireEvent.keyDown(box(), { key: 'Escape' })
    await settle()
    expect(status).not.toHaveAttribute('data-drawn')
    expect(below.className).not.toContain('@md/toolbar:flex-[0_0_auto]')
  })

  it('Escape puts back the applied text', async () => {
    serve({})
    render(<Harness onApply={vi.fn()} />)
    fireEvent.click(query())
    await settle()
    fireEvent.change(box(), { target: { value: 'kev=' } })
    fireEvent.keyDown(box(), { key: 'Escape' })
    expect(box().value).toBe('practice!=compliance severity=critical state=open')
  })

  it('Ctrl+/ switches modes; the phone toggle says its state', async () => {
    serve({})
    render(<Harness onApply={vi.fn()} />)
    const toggle = () => screen.getByRole('button', { name: 'Query mode' })
    expect(toggle()).toHaveAttribute('aria-pressed', 'false')
    fireEvent.keyDown(window, { key: '/', ctrlKey: true })
    await settle()
    expect(toggle()).toHaveAttribute('aria-pressed', 'true')
    expect(box().value).toBe('practice!=compliance severity=critical state=open')
  })

  it('a link in Query mode opens with the text in the field, unfocused, checked once', async () => {
    const text =
      'practice!=compliance severity=critical state=open (is_in_kev=true OR severity=high)'
    serve({ [text]: result({ text, advanced: true }) })
    render(<Harness onApply={vi.fn()} fq="is_in_kev=true OR severity=high" initialActive />)
    await settle()
    expect(query()).toHaveAttribute('aria-pressed', 'true')
    expect(box().value).toBe(text)
    expect(document.activeElement).not.toBe(box())
    // The printer (params) and one check of the whole text.
    expect(api.parse).toHaveBeenCalledTimes(2)
    expect(api.parse).toHaveBeenLastCalledWith({ entity: 'findings', text })
    expect(box()).not.toHaveAttribute('aria-invalid', 'true')
  })

  it('a link in Query mode whose text the server refuses opens in Query mode with the problem', async () => {
    serve({})
    render(<Harness onApply={vi.fn()} fq="severity=bogus" initialActive />)
    await settle()
    expect(query()).toHaveAttribute('aria-pressed', 'true')
    expect(box().value).toBe('practice!=compliance severity=critical state=open (severity=bogus)')
    expect(box()).toHaveAttribute('aria-invalid', 'true')
    expect(screen.getByText(/Column 11\./)).toBeTruthy()
  })

  it('switching to Query mode by hand checks nothing more and takes the focus', async () => {
    serve({})
    render(<Harness onApply={vi.fn()} fq="kev=true" />)
    fireEvent.click(query())
    await settle()
    // Only the printer: the person is about to edit the text.
    expect(api.parse).toHaveBeenCalledTimes(1)
    expect(document.activeElement).toBe(box())
  })

  describe('with a saved view open', () => {
    const VIEW_TEXT = 'severity=critical OR is_in_kev=true'
    const doc = (text: string) => ({ v: 1, text })
    const EDITED = result({ text: 'severity=high OR is_in_kev=true', advanced: true })

    it("the field holds the view's own text, printed from its document in one request", async () => {
      serve({})
      render(<Harness onApply={vi.fn()} params="" base={doc(VIEW_TEXT)} initialActive />)
      await settle()
      expect(box().value).toBe(VIEW_TEXT)
      expect(api.parse).toHaveBeenCalledTimes(1)
      expect(api.parse).toHaveBeenCalledWith({ entity: 'findings', document: doc(VIEW_TEXT) })
      // Typing asks nothing more.
      fireEvent.change(box(), { target: { value: `${VIEW_TEXT} x` } })
      await settle()
      expect(api.parse).toHaveBeenCalledTimes(1)
    })

    it('unchanged, Enter and the switch to Basic write nothing: the URL stays the view', async () => {
      serve({ [VIEW_TEXT]: result({ text: VIEW_TEXT, advanced: true }) })
      const onApply = vi.fn()
      render(<Harness onApply={onApply} params="" base={doc(VIEW_TEXT)} initialActive />)
      await settle()
      fireEvent.keyDown(box(), { key: 'Enter' })
      await settle()
      fireEvent.click(basic())
      await settle()
      expect(onApply).not.toHaveBeenCalled()
      expect(basic()).toHaveAttribute('aria-pressed', 'true')
    })

    it('round trip: another text is applied whole; the saved view reopened shows the new text', async () => {
      serve({ [EDITED.text]: EDITED })
      const onApply = vi.fn()
      const { rerender } = render(
        <Harness onApply={onApply} params="" base={doc(VIEW_TEXT)} initialActive />
      )
      await settle()
      fireEvent.change(box(), { target: { value: EDITED.text } })
      fireEvent.keyDown(box(), { key: 'Enter' })
      await settle()
      // The page gets the whole text (it writes it with from_view, no view).
      expect(onApply).toHaveBeenCalledWith(EDITED)
      // Save changes stored it; the view is open again with its new document.
      rerender(<Harness onApply={onApply} params="" base={doc(EDITED.text)} initialActive />)
      await settle()
      expect(box().value).toBe(EDITED.text)
    })

    it('what the URL adds on top follows the view text, the view text grouped', async () => {
      serve({})
      render(<Harness onApply={vi.fn()} base={doc(VIEW_TEXT)} initialActive />)
      await settle()
      expect(box().value).toBe(`(${VIEW_TEXT}) ${PRINTED.text}`)
      expect(joinViewText('', 'a=1')).toBe('a=1')
      expect(joinViewText('a=1', '')).toBe('a=1')
    })

    it('a view document the printer refuses leaves the field usable', async () => {
      api.parse.mockRejectedValue(new Error('400'))
      render(<Harness onApply={vi.fn()} params="" base={doc(VIEW_TEXT)} initialActive />)
      await settle()
      expect(box().value).toBe('')
      expect(box()).toBeEnabled()
    })
  })

  it('the mode is a URL param: absent is Basic, a saved view keeps it', () => {
    expect(queryModeIn(new URLSearchParams('severity=high'))).toBe(false)
    expect(queryModeIn(new URLSearchParams('mode=query&fq=a'))).toBe(true)
    expect(queryModeIn(new URLSearchParams('mode=basic'))).toBe(false)
    const on = withQueryMode(new URLSearchParams('fq=a&view=v'), true)
    expect(on.toString()).toBe('fq=a&view=v&mode=query')
    expect(withQueryMode(on, false).toString()).toBe('fq=a&view=v')
    expect(modePageParams(true)).toEqual({ mode: 'query' })
    expect(modePageParams(false)).toEqual({ mode: 'basic' })
    expect(viewOpensInQueryMode({ page_params: { mode: 'query' } })).toBe(true)
    expect(viewOpensInQueryMode({ page_params: { mode: 'basic' } })).toBe(false)
    expect(viewOpensInQueryMode({})).toBe(false)
  })

  it('an fq filter is shown after the printed params, both applying', () => {
    expect(joinFilterText('state=open', 'kev=true OR epss>=0.5')).toBe(
      'state=open (kev=true OR epss>=0.5)'
    )
    expect(joinFilterText('', 'kev=true')).toBe('kev=true')
    expect(joinFilterText('state=open', null)).toBe('state=open')
  })
})
