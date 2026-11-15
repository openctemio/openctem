import { describe, expect, it, vi, beforeEach } from 'vitest'
import { act, fireEvent, render, screen } from '@testing-library/react'
import { useState } from 'react'
import { ListSearch } from '@/features/shared/components/list-search'
import {
  joinFilterText,
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

/** The server: params print as PRINTED; texts answer from a table. */
function serve(texts: Record<string, ParseResult>) {
  api.parse.mockImplementation((req: ParseRequest) =>
    Promise.resolve(req.params !== undefined ? PRINTED : (texts[req.text ?? ''] ?? REFUSED))
  )
}

function Harness({
  onApply,
  fq = null,
  initialActive = false,
}: {
  onApply: (r: ParseResult) => void
  fq?: string | null
  /** The page URL says Query mode (a link, a reload). */
  initialActive?: boolean
}) {
  // The page keeps the mode in its URL; here, in state.
  const [active, setActive] = useState(initialActive)
  const mode = useListQueryMode({
    entity: 'findings',
    active,
    onActiveChange: setActive,
    fq,
    params: 'severity=critical&state=open&practice_not=compliance',
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
