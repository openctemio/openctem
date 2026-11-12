/**
 * New Scan dynamic target settings (RFC-068): how address ranges are scanned
 * (the choice shown is the mode the API runs), what a selector holds now,
 * and the freshness options with their one-line summary.
 */
import * as React from 'react'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import type { ScanTargetOptions } from '@/lib/api/scan-types'
import {
  CidrModeChoice,
  SelectorOptions,
  selectorPreviewText,
} from '../new-scan/dynamic-target-controls'
import { enTranslate } from '../../lib/translate'

function Ranges({
  initial,
  onChange,
  savedScan,
  livenessAvailable,
}: {
  initial?: ScanTargetOptions
  onChange?: (o: ScanTargetOptions) => void
  savedScan?: boolean
  livenessAvailable?: boolean
}) {
  const [options, setOptions] = React.useState<ScanTargetOptions | undefined>(initial)
  return (
    <CidrModeChoice
      options={options}
      onChange={(o) => {
        setOptions(o)
        onChange?.(o)
      }}
      savedScan={savedScan}
      livenessAvailable={livenessAvailable}
    />
  )
}

describe('CidrModeChoice', () => {
  it('a new scan that can find live hosts shows live hosts first chosen', async () => {
    const onChange = vi.fn()
    const user = userEvent.setup()
    render(<Ranges onChange={onChange} livenessAvailable />)
    expect(screen.getByRole('radio', { name: 'Live hosts first' })).toBeChecked()
    expect(screen.queryByText(/No choice saved/)).not.toBeInTheDocument()
    // The chosen option's hint, one line, instead of a paragraph per option.
    expect(screen.getByText(/A light probe finds the live addresses/)).toBeInTheDocument()
    expect(screen.queryByText('The scanner probes every address in it.')).not.toBeInTheDocument()

    await user.click(screen.getByRole('radio', { name: 'Every address' }))
    expect(onChange).toHaveBeenLastCalledWith({ cidr_mode: 'sweep' })
    expect(screen.getByText('The scanner probes every address in it.')).toBeInTheDocument()
    await user.click(screen.getByRole('radio', { name: 'Known hosts only' }))
    expect(onChange).toHaveBeenLastCalledWith({ cidr_mode: 'inventory' })
  })

  it('is live hosts first while the workflow loads (the API decides the same way)', () => {
    render(<Ranges />)
    expect(screen.getByRole('radio', { name: 'Live hosts first' })).toBeChecked()
  })

  // The mismatch the owner saw: a new scan whose workflow has no Host
  // discovery is swept by the API; the choice must say so, not live hosts.
  it('a new workflow scan without Host discovery shows every address chosen, live hosts disabled', () => {
    render(<Ranges livenessAvailable={false} />)
    expect(screen.getByRole('radio', { name: 'Every address' })).toBeChecked()
    expect(screen.getByRole('radio', { name: 'Live hosts first' })).toBeDisabled()
    expect(screen.getByText(/needs a Host discovery step/)).toBeInTheDocument()
    expect(screen.getByText(/this workflow has no Host discovery step/)).toBeInTheDocument()
  })

  // Decision A1 (owner, 2026-10-13): a saved scan is never switched to live
  // hosts first by an edit; it is suggested, and switches with one click.
  it('shows a saved scan without a mode as sweeping, with the suggestion', async () => {
    const onChange = vi.fn()
    const user = userEvent.setup()
    render(<Ranges onChange={onChange} savedScan livenessAvailable />)
    expect(screen.getByRole('radio', { name: 'Every address' })).toBeChecked()
    expect(screen.getByText(/keeps doing so until you choose otherwise/)).toBeInTheDocument()
    expect(screen.getByTestId('liveness-suggestion')).toHaveTextContent(
      'Live hosts first (recommended)'
    )
    expect(onChange).not.toHaveBeenCalled()

    await user.click(screen.getByRole('button', { name: 'Use live hosts first' }))
    expect(onChange).toHaveBeenLastCalledWith({ cidr_mode: 'liveness' })
    expect(screen.getByRole('radio', { name: 'Live hosts first' })).toBeChecked()
    expect(screen.queryByTestId('liveness-suggestion')).not.toBeInTheDocument()
  })

  it('suggests nothing when the scan cannot find live hosts', () => {
    render(<Ranges savedScan livenessAvailable={false} />)
    expect(screen.getByRole('radio', { name: 'Every address' })).toBeChecked()
    expect(screen.queryByTestId('liveness-suggestion')).not.toBeInTheDocument()
  })

  it('keeps a saved live hosts first choice', () => {
    render(<Ranges initial={{ cidr_mode: 'liveness' }} savedScan livenessAvailable />)
    expect(screen.getByRole('radio', { name: 'Live hosts first' })).toBeChecked()
    expect(screen.queryByTestId('liveness-suggestion')).not.toBeInTheDocument()
  })
})

describe('selectorPreviewText', () => {
  const wildcard = { kind: 'wildcard' as const, target: '*.example.com', value: 'example.com' }
  const cidr = { kind: 'cidr' as const, target: '203.0.113.0/24', value: '203.0.113.0/24' }
  const state = { enabled: true, isLoading: false }

  it('says what a wildcard or an inventory range holds now, and when a run is capped', () => {
    expect(
      selectorPreviewText(
        enTranslate,
        wildcard,
        { selector: wildcard, total: 42, recent: [] },
        state
      )
    ).toMatch(/example\.com and 42 known names now/)
    expect(
      selectorPreviewText(
        enTranslate,
        wildcard,
        { selector: wildcard, total: 9000, recent: [] },
        state
      )
    ).toMatch(/a run takes the 5,000 seen most recently/)
    expect(
      selectorPreviewText(enTranslate, cidr, { selector: cidr, total: 1, recent: [] }, state)
    ).toMatch(/1 known host in this range now/)
  })

  it('says why nothing is shown to someone who cannot read assets', () => {
    expect(
      selectorPreviewText(enTranslate, wildcard, undefined, { enabled: false, isLoading: false })
    ).toMatch(/shown to people who can read assets/)
  })
})

describe('SelectorOptions', () => {
  it('summarises the options on its header and sets them', async () => {
    const onChange = vi.fn()
    const user = userEvent.setup()
    function Harness() {
      const [o, setO] = React.useState<ScanTargetOptions | undefined>(undefined)
      return (
        <SelectorOptions
          options={o}
          onChange={(next) => {
            setO(next)
            onChange(next)
          }}
          workflow
        />
      )
    }
    render(<Harness />)
    expect(screen.getByTestId('options-summary')).toHaveTextContent(
      'Assets seen at any time, only names that resolve'
    )
    await user.click(screen.getByRole('button', { name: /Dynamic targets/ }))
    expect(screen.getByText(/Discovery steps add what they find/)).toBeInTheDocument()
    await user.click(screen.getByRole('checkbox', { name: /Include assets not seen for a while/ }))
    expect(onChange).toHaveBeenLastCalledWith({ include_stale: true })
    expect(screen.getByTestId('options-summary')).toHaveTextContent(
      'Assets seen at any time, includes stale assets, only names that resolve'
    )
  })
})
