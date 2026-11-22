import { render } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import type { ColumnDef } from '@tanstack/react-table'

let captured: ColumnDef<unknown>[] = []

vi.mock('@/features/shared', () => ({
  DataTable: (p: { columns: ColumnDef<unknown>[] }) => {
    captured = p.columns
    return null
  },
  DataTableColumnHeader: () => null,
}))
vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('@/components/link', () => ({ default: () => null }))
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({ t: (k: string) => k }),
}))

import { FindingQueue } from '../components/finding-queue'

function cols() {
  render(
    <FindingQueue
      tab="assigned"
      rows={[]}
      total={0}
      isLoading={false}
      error={null}
      onRetry={() => {}}
      empty={null}
    />
  )
  return captured.map((c) => ({
    id: (c as { accessorKey?: string }).accessorKey ?? c.id,
    meta: c.meta as { kind?: string; hideBelow?: number; primary?: boolean },
  }))
}

describe('FindingQueue columns', () => {
  it('sizes every column by its kind, so a tablet frame never cuts one', () => {
    const byId = Object.fromEntries(cols().map((c) => [c.id, c.meta]))
    expect(byId.priority_class.kind).toBe('priority')
    expect(byId.title.primary).toBe(true)
    expect(byId.severity.kind).toBe('severity')
    expect(byId.sla.kind).toBe('due')
    expect(byId.status.kind).toBe('status')
  })

  it('drops the status column on a narrow frame instead of cutting it', () => {
    const byId = Object.fromEntries(cols().map((c) => [c.id, c.meta]))
    expect(byId.status.hideBelow).toBe(700)
  })
})
