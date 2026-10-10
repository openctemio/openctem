/**
 * Settings › Asset sources (RFC-069 §12): ranked lists per attribute class,
 * reordered by keyboard (Space, arrows, Space / Escape) or with the buttons,
 * TTL and trust per row, customise and reset per class, the preview of
 * unsaved changes, what is saved, and read-only without the right to edit.
 */
import { describe, it, expect, vi } from 'vitest'
import { fireEvent, render, screen, within, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AssetSourcesSettingsForm } from '../asset-sources-settings'
import type { ReconciliationSettings, SourceRule } from '../../lib/attribute-sources'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

// Radix Select needs these in jsdom.
Element.prototype.scrollIntoView = vi.fn()
Element.prototype.hasPointerCapture = vi.fn(() => false)
Element.prototype.releasePointerCapture = vi.fn()

const r = (source: string, ttl_days: number, trusted = true): SourceRule => ({
  source,
  ttl_days,
  trusted,
})
const defaults = {
  default: [r('integration', 30), r('scan', 30), r('import', 90), r('feed', 30)],
  classes: {
    ownership: [r('integration', 30), r('import', 90), r('scan', 30, false), r('feed', 30, false)],
    network: [r('scan', 30), r('integration', 30), r('import', 90), r('feed', 30)],
  },
}
const settings: ReconciliationSettings = {
  saved: { default: [], classes: {} },
  effective: defaults,
  defaults,
  classes: [
    { class: 'identity', attributes: [] },
    { class: 'network', attributes: ['exposure'] },
    { class: 'software', attributes: [] },
    { class: 'ownership', attributes: ['criticality', 'owner_ref', 'data_classification'] },
    { class: 'cloud_tags', attributes: [] },
    { class: 'lifecycle', attributes: [] },
  ],
  sources: [{ kind: 'scan', name: 'nmap', last_seen: new Date().toISOString(), assets: 3 }],
}

function setup(canEdit = true) {
  const onSave = vi.fn().mockResolvedValue(undefined)
  const onPreview = vi.fn().mockResolvedValue({
    scanned_assets: 10,
    truncated: false,
    changed_assets: 2,
    changed_values: 3,
    conflicts: 1,
    samples: [
      {
        asset_id: 'a1',
        asset_name: 'db.example.com',
        attribute: 'criticality',
        current: 'high',
        next: 'low',
        next_source: 'import:csv',
        conflict: false,
      },
    ],
  })
  render(
    <AssetSourcesSettingsForm
      settings={settings}
      canEdit={canEdit}
      onSave={onSave}
      onPreview={onPreview}
    />
  )
  return { onSave, onPreview, user: userEvent.setup() }
}

const defaultList = () => screen.getByRole('list', { name: 'Default source order' })
const order = (list: HTMLElement) =>
  within(list)
    .getAllByTestId(/^source-row-/)
    .map((el) => el.getAttribute('data-testid')?.replace('source-row-', ''))

describe('AssetSourcesSettingsForm', () => {
  it('shows the pinned lock row, the default list and the customised classes', () => {
    setup()
    expect(within(defaultList()).getByText(/always wins/)).toBeInTheDocument()
    expect(order(defaultList())).toEqual(['integration', 'scan', 'import', 'feed'])
    expect(
      screen.getByRole('list', { name: 'Ownership and business context source order' })
    ).toBeInTheDocument()
    expect(screen.getAllByText('Uses the default order.')).toHaveLength(4)
    expect(screen.getByText('Applies to: Exposure')).toBeInTheDocument()
  })

  it('reorders by keyboard: Space picks up, arrows move, Space drops, announced', async () => {
    const { onSave, user } = setup()
    const handle = within(defaultList()).getByRole('button', {
      name: 'Reorder Sensors and scanners',
    })
    handle.focus()
    fireEvent.keyDown(handle, { key: ' ' })
    expect(
      screen
        .getAllByRole('status')
        .some((s) => /Picked up Sensors and scanners/.test(s.textContent ?? ''))
    ).toBe(true)
    fireEvent.keyDown(handle, { key: 'ArrowUp' })
    fireEvent.keyDown(
      within(defaultList()).getByRole('button', { name: 'Reorder Sensors and scanners' }),
      { key: ' ' }
    )
    expect(order(defaultList())).toEqual(['scan', 'integration', 'import', 'feed'])
    expect(
      screen
        .getAllByRole('status')
        .some((s) => /dropped at position 1 of 4/.test(s.textContent ?? ''))
    ).toBe(true)

    await user.click(screen.getByRole('button', { name: /Save changes/ }))
    expect(onSave).toHaveBeenCalledTimes(1)
    expect(onSave.mock.calls[0][0].default.map((x: SourceRule) => x.source)).toEqual([
      'scan',
      'integration',
      'import',
      'feed',
    ])
    // Classes not customised are not sent; customised ones are.
    expect(Object.keys(onSave.mock.calls[0][0].classes).sort()).toEqual(['network', 'ownership'])
  })

  it('Escape cancels a keyboard move', () => {
    setup()
    const handle = within(defaultList()).getByRole('button', { name: 'Reorder Imports' })
    fireEvent.keyDown(handle, { key: 'Enter' })
    fireEvent.keyDown(handle, { key: 'ArrowDown' })
    expect(order(defaultList())).toEqual(['integration', 'scan', 'feed', 'import'])
    fireEvent.keyDown(within(defaultList()).getByRole('button', { name: 'Reorder Imports' }), {
      key: 'Escape',
    })
    expect(order(defaultList())).toEqual(['integration', 'scan', 'import', 'feed'])
    expect(
      screen.getAllByRole('status').some((s) => /Move cancelled/.test(s.textContent ?? ''))
    ).toBe(true)
  })

  it('reorders with the up and down buttons (touch screens)', async () => {
    const { user } = setup()
    await user.click(within(defaultList()).getByRole('button', { name: 'Move Imports up' }))
    expect(order(defaultList())).toEqual(['integration', 'import', 'scan', 'feed'])
    expect(
      within(defaultList()).getByRole('button', { name: 'Move Connectors (integrations) up' })
    ).toBeDisabled()
  })

  it('edits TTL and trust per row and refuses an invalid TTL', async () => {
    const { onSave, user } = setup()
    await user.click(
      within(defaultList()).getByRole('switch', {
        name: 'Feeds (program feeds, passive data) may update any attribute',
      })
    )
    const ttl = within(defaultList()).getByLabelText('Days Imports counts')
    await user.clear(ttl)
    await user.type(ttl, '5000')
    expect(screen.getByRole('alert')).toHaveTextContent(/whole number of days/)
    expect(screen.getByRole('button', { name: /Save changes/ })).toBeDisabled()
    await user.clear(ttl)
    await user.type(ttl, '45')
    await user.click(screen.getByRole('button', { name: /Save changes/ }))
    const saved = onSave.mock.calls[0][0]
    expect(saved.default.find((x: SourceRule) => x.source === 'feed').trusted).toBe(false)
    expect(saved.default.find((x: SourceRule) => x.source === 'import').ttl_days).toBe(45)
  })

  it('customises a class from the default list and resets it', async () => {
    const { onSave, user } = setup()
    // identity, network, software, ...: software is the third class.
    await user.click(screen.getAllByRole('switch', { name: 'Customise for this class' })[2])
    const software = screen.getByRole('list', { name: 'Software source order' })
    expect(order(software)).toEqual(['integration', 'scan', 'import', 'feed'])
    await user.click(within(software).getByRole('button', { name: 'Move Sensors and scanners up' }))
    await user.click(screen.getByRole('button', { name: /Save changes/ }))
    expect(onSave.mock.calls[0][0].classes.software.map((x: SourceRule) => x.source)).toEqual([
      'scan',
      'integration',
      'import',
      'feed',
    ])
    // Reset to default: the class inherits again and is not sent.
    // Customised now: network, software, ownership (page order).
    const resets = screen.getAllByRole('button', { name: /Reset to default/ })
    expect(resets).toHaveLength(3)
    await user.click(resets[1])
    expect(screen.queryByRole('list', { name: 'Software source order' })).not.toBeInTheDocument()
  })

  it('ranks a source the organization has as its own row', async () => {
    const { onSave, user } = setup()
    await user.click(screen.getAllByRole('combobox', { name: 'Rank a source separately' })[0])
    await user.click(await screen.findByRole('option', { name: 'nmap (Scan)' }))
    expect(order(defaultList())).toEqual(['integration', 'scan:nmap', 'scan', 'import', 'feed'])
    await user.click(screen.getByRole('button', { name: /Save changes/ }))
    expect(onSave.mock.calls[0][0].default[1]).toEqual({
      source: 'scan:nmap',
      ttl_days: 30,
      trusted: true,
    })
  })

  it('previews the unsaved order before saving', async () => {
    const { onPreview, onSave, user } = setup()
    await user.click(within(defaultList()).getByRole('button', { name: 'Move Imports up' }))
    await user.click(screen.getByRole('button', { name: /^Preview$/ }))
    await waitFor(() => expect(onPreview).toHaveBeenCalledTimes(1))
    expect(onPreview.mock.calls[0][0].default[1].source).toBe('import')
    expect(onPreview.mock.calls[0][1]).toBeUndefined()
    const result = await screen.findByTestId('preview-result')
    expect(result).toHaveTextContent('2 of 10 assets would change (3 values). 1 conflicts.')
    expect(result).toHaveTextContent('db.example.com')
    expect(onSave).not.toHaveBeenCalled()
  })

  it('is read-only without the right to edit', () => {
    setup(false)
    expect(screen.queryByRole('button', { name: /Save changes/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Reorder/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Move / })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Preview$/ })).not.toBeInTheDocument()
    expect(within(defaultList()).getByLabelText('Days Imports counts')).toBeDisabled()
  })
})
