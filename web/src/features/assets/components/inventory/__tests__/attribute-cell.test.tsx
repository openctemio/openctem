import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { Asset } from '../../../types'
import type { TypeAttribute } from '@/features/asset-types/lib/type-view'
import { AttributeCell } from '../attribute-cell'
import { TooltipProvider } from '@/components/ui/tooltip'

function asset(metadata: Record<string, unknown>, extra: Partial<Asset> = {}): Asset {
  return { id: 'a1', name: 'x', type: 'host', metadata, tags: [], ...extra } as unknown as Asset
}

function cell(a: Asset, attribute: TypeAttribute) {
  return render(
    <TooltipProvider>
      <AttributeCell asset={a} attribute={attribute} />
    </TooltipProvider>
  )
}

describe('AttributeCell', () => {
  it('shows a dash, never a default, for a value the asset does not carry', () => {
    cell(asset({}), { key: 'is_virtual', kind: 'bool', facet: true })
    expect(screen.getByText('—')).toBeInTheDocument()
  })

  it('renders by kind: yes/no, enum badge, number', () => {
    const { unmount } = cell(asset({ is_virtual: true }), {
      key: 'is_virtual',
      kind: 'bool',
      facet: true,
    })
    expect(screen.getByText('Yes')).toBeInTheDocument()
    unmount()
    const r2 = cell(asset({ os_family: 'linux' }), { key: 'os_family', kind: 'enum', facet: true })
    expect(screen.getByText('linux')).toBeInTheDocument()
    r2.unmount()
    cell(asset({ cpu_count: 8 }), { key: 'cpu_count', kind: 'int', facet: false })
    expect(screen.getByText('8')).toBeInTheDocument()
  })

  it('shows the first list value and how many more, synonyms folded', () => {
    cell(asset({ ip_addresses: ['10.0.0.1', '10.0.0.2', '10.0.0.3'] }), {
      key: 'ip_addresses',
      kind: 'list',
      facet: false,
    })
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument()
    expect(screen.getByText('+2')).toBeInTheDocument()
  })

  it('marks an expiry already past in red', () => {
    cell(asset({ not_after: '2000-01-01T00:00:00Z' }), {
      key: 'not_after',
      kind: 'time',
      facet: false,
    })
    expect(screen.getByText(/ago/)).toHaveClass('text-destructive')
  })

  it('reads a repository fact from its extension when properties do not have it', () => {
    cell(
      asset({}, { type: 'repository', repository: { visibility: 'private' } } as Partial<Asset>),
      { key: 'visibility', kind: 'enum', values: ['public', 'private'], facet: true }
    )
    expect(screen.getByText('private')).toBeInTheDocument()
  })

  it('never links a non-http value', () => {
    cell(asset({ documentation_url: 'javascript:alert(1)' }), {
      key: 'documentation_url',
      kind: 'string',
      facet: false,
    })
    expect(screen.queryByRole('link')).toBeNull()
  })
})
