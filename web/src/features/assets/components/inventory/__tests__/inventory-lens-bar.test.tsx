/**
 * The inventory lens bar: lens pills with scoped counts (a lens with no asset
 * is hidden), an "Other" pill for assets outside every lens, type chips that
 * write `?types=`, keyboard movement along a row, and the data-scope rule that
 * counts come from the caller's own (scoped) stats.
 */
import { describe, it, expect, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { InventoryLensBar } from '../inventory-lens-bar'
import { lensCounts, lensOfType } from '../../../lib/inventory-lenses'
import { parseInventoryFilters, serializeInventoryFilters } from '../../../lib/inventory-url'
import type { AssetTypeRegistry } from '@/features/asset-types/lib/asset-registry'

const REGISTRY = {
  lenses: [
    { id: 'external_surface', label: 'External surface' },
    { id: 'applications', label: 'Applications' },
    { id: 'containers_k8s', label: 'Containers & Kubernetes' },
    { id: 'data', label: 'Data' },
    { id: 'identities', label: 'Identities' },
  ],
  types: [
    { type: 'subdomain', label: 'Subdomain', lens: 'external_surface' },
    { type: 'service', label: 'Service', lens: 'external_surface' },
    {
      type: 'http_service',
      label: 'HTTP Service',
      lens: 'external_surface',
      alias_of: { type: 'service', sub_type: 'http' },
    },
    { type: 'ip_address', label: 'IP Address', lens: 'external_surface' },
    { type: 'application', label: 'Application', lens: 'applications' },
    { type: 'storage', label: 'Storage', lens: 'data' },
    { type: 'container', label: 'Container', lens: 'containers_k8s' },
    {
      type: 'container_registry',
      label: 'Container Registry',
      lens: 'containers_k8s',
      alias_of: { type: 'storage', sub_type: 'container_registry' },
    },
    { type: 'unclassified', label: 'Unclassified', class: 'other' },
  ],
} as unknown as AssetTypeRegistry

// What a scoped member's /assets/stats returns: only their assets.
const SCOPED = {
  subdomain: 105,
  service: 60,
  'service/http': 42,
  ip_address: 70,
  application: 4,
  'storage/bucket': 3,
  'storage/container_registry': 2,
  unclassified: 1,
}

describe('lensCounts', () => {
  it('places every row once: aliases in their own lens only when it differs', () => {
    const c = lensCounts(REGISTRY, SCOPED)
    expect(c.byLens).toEqual({ external_surface: 277, applications: 4, data: 3, containers_k8s: 2 })
    // http_service rows count under Service (same lens), the registry under Containers.
    expect(c.chips.external_surface?.map((x) => [x.type, x.count])).toEqual([
      ['subdomain', 105],
      ['service', 102],
      ['ip_address', 70],
    ])
    expect(c.chips.containers_k8s).toEqual([
      { type: 'container_registry', label: 'Container Registry', count: 2 },
    ])
    expect(c.other).toBe(1)
    expect(c.otherTypes).toEqual(['unclassified'])
  })

  it('a single picked type keeps its lens', () => {
    expect(lensOfType(REGISTRY, 'ip_address')).toBe('external_surface')
    expect(lensOfType(REGISTRY, 'unclassified')).toBeUndefined()
  })
})

describe('InventoryLensBar', () => {
  const counts = lensCounts(REGISTRY, SCOPED)

  it('shows counts, hides lenses with no asset and adds Other', () => {
    render(
      <InventoryLensBar
        registry={REGISTRY}
        value={undefined}
        counts={counts}
        total={285}
        onChange={vi.fn()}
      />
    )
    const bar = screen.getByRole('toolbar', { name: 'Asset lens' })
    const names = within(bar)
      .getAllByRole('button')
      .map((b) => b.textContent)
    expect(names).toEqual([
      'All285',
      'External surface277',
      'Applications4',
      'Containers & Kubernetes2',
      'Data3',
      'Other1',
    ])
    expect(within(bar).queryByRole('button', { name: /Identities/ })).not.toBeInTheDocument()
    expect(within(bar).getByRole('button', { name: /^All/ })).toHaveAttribute(
      'aria-pressed',
      'true'
    )
  })

  it('Other selects the unclassified types', async () => {
    const onChange = vi.fn()
    render(
      <InventoryLensBar registry={REGISTRY} value={undefined} counts={counts} onChange={onChange} />
    )
    await userEvent.click(screen.getByRole('button', { name: /^Other/ }))
    expect(onChange).toHaveBeenCalledWith({ lens: undefined, types: ['unclassified'] })
  })

  it('type chips of the picked lens toggle ?types= and survive the URL round trip', async () => {
    const onChange = vi.fn()
    const { rerender } = render(
      <InventoryLensBar
        registry={REGISTRY}
        value="external_surface"
        counts={counts}
        onChange={onChange}
      />
    )
    const chips = screen.getByRole('toolbar', { name: 'Asset types in External surface' })
    expect(
      within(chips)
        .getAllByRole('button')
        .map((b) => b.textContent)
    ).toEqual(['Subdomain105', 'Service102', 'IP Address70'])
    await userEvent.click(within(chips).getByRole('button', { name: /^Subdomain/ }))
    expect(onChange).toHaveBeenLastCalledWith({ lens: 'external_surface', types: ['subdomain'] })

    rerender(
      <InventoryLensBar
        registry={REGISTRY}
        value="external_surface"
        types={['subdomain']}
        counts={counts}
        onChange={onChange}
      />
    )
    expect(screen.getByRole('button', { name: /^Subdomain/ })).toHaveAttribute(
      'aria-pressed',
      'true'
    )
    await userEvent.click(screen.getByRole('button', { name: /^IP Address/ }))
    expect(onChange).toHaveBeenLastCalledWith({
      lens: 'external_surface',
      types: ['subdomain', 'ip_address'],
    })
    // Deselecting the last chip clears ?types=.
    await userEvent.click(screen.getByRole('button', { name: /^Subdomain/ }))
    expect(onChange).toHaveBeenLastCalledWith({ lens: 'external_surface', types: undefined })

    const qs = serializeInventoryFilters({
      lens: 'external_surface',
      types: ['subdomain', 'ip_address'],
    } as never)
    const back = parseInventoryFilters(new URLSearchParams(qs.toString()))
    expect(back.lens).toBe('external_surface')
    expect(back.types).toEqual(['subdomain', 'ip_address'])
  })

  it('moves along a row with the arrow keys, Home and End', async () => {
    render(
      <InventoryLensBar
        registry={REGISTRY}
        value={undefined}
        counts={counts}
        total={285}
        onChange={vi.fn()}
      />
    )
    const bar = screen.getByRole('toolbar', { name: 'Asset lens' })
    const buttons = within(bar).getAllByRole('button')
    // One tab stop per row: the pressed pill.
    expect(buttons.filter((b) => b.tabIndex === 0)).toHaveLength(1)
    buttons[0].focus()
    await userEvent.keyboard('{ArrowRight}')
    expect(buttons[1]).toHaveFocus()
    await userEvent.keyboard('{End}')
    expect(buttons[buttons.length - 1]).toHaveFocus()
    await userEvent.keyboard('{ArrowRight}')
    expect(buttons[0]).toHaveFocus()
  })

  it('data scope: a lens whose assets are all outside the caller’s scope is not shown or counted', () => {
    // The tenant has identities, but none in this member's scope: the scoped
    // stats carry no key for them, so the pill neither shows nor leaks a number.
    const scoped = lensCounts(REGISTRY, { subdomain: 3 })
    render(
      <InventoryLensBar
        registry={REGISTRY}
        value={undefined}
        counts={scoped}
        total={3}
        onChange={vi.fn()}
      />
    )
    const names = screen.getAllByRole('button').map((b) => b.textContent)
    expect(names).toEqual(['All3', 'External surface3'])
  })

  it('shows every lens, without numbers, until the counts load', () => {
    render(<InventoryLensBar registry={REGISTRY} value={undefined} onChange={vi.fn()} />)
    expect(screen.getAllByRole('button').map((b) => b.textContent)).toEqual([
      'All',
      'External surface',
      'Applications',
      'Containers & Kubernetes',
      'Data',
      'Identities',
    ])
  })
})
