/**
 * One filled button per screen (acceptance review 2026-11-18, K10): an empty
 * state's action was filled beside the page header's filled main action
 * ("New group" twice on Asset groups, "New workflow" and "Create workflow" on
 * Automations). The empty state's action is filled only when no other filled
 * button is shown; otherwise it is an outline button. Without a header main
 * action it stays filled (Findings first run: "Run a scan").
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ColumnDef } from '@tanstack/react-table'
import { Inbox } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { EmptyState } from '../empty-state'
import { DataTable } from '../data-table'

// jsdom has no layout: every element counts as drawn on the screen.
const proto = Element.prototype
const saved = {
  rects: Object.getOwnPropertyDescriptor(proto, 'getClientRects'),
  box: Object.getOwnPropertyDescriptor(proto, 'getBoundingClientRect'),
}
beforeEach(() => {
  Object.defineProperty(proto, 'getClientRects', {
    configurable: true,
    value: () => [{ top: 10, bottom: 46, height: 36 }],
  })
  Object.defineProperty(proto, 'getBoundingClientRect', {
    configurable: true,
    value: () => ({ top: 10, bottom: 46, height: 36, left: 0, right: 100, width: 100 }),
  })
})
afterEach(() => {
  if (saved.rects) Object.defineProperty(proto, 'getClientRects', saved.rects)
  if (saved.box) Object.defineProperty(proto, 'getBoundingClientRect', saved.box)
  vi.restoreAllMocks()
})

const variantOf = (name: string) =>
  screen.getByRole('button', { name }).getAttribute('data-variant')

/** A permission wrapper such as `Can`: the button sits in its children. */
function Gate({ children }: { children: React.ReactNode }) {
  return <>{children}</>
}

describe('one filled button per screen', () => {
  it('draws the empty state action as an outline button beside the header main action', () => {
    render(
      <>
        <Button>New group</Button>
        <EmptyState
          icon={Inbox}
          title="No groups yet"
          action={
            <Gate>
              <Button>Create group</Button>
            </Gate>
          }
        />
      </>
    )
    expect(variantOf('New group')).toBe('default')
    expect(variantOf('Create group')).toBe('outline')
  })

  it('keeps the empty state action filled when the page shows no other filled button', () => {
    render(
      <>
        <Button variant="outline">Export</Button>
        <EmptyState icon={Inbox} title="No findings yet" action={<Button>Run a scan</Button>} />
      </>
    )
    expect(variantOf('Run a scan')).toBe('default')
  })

  it('does the same for a list whose empty block is the page own', () => {
    const columns: ColumnDef<{ id: string }>[] = [{ accessorKey: 'id', header: 'Id' }]
    render(
      <>
        <Button>New workflow</Button>
        <DataTable
          columns={columns}
          data={[]}
          emptyState={{
            nothingYet: (
              <div>
                <p>No workflows yet</p>
                <Button variant="signal">Create workflow</Button>
              </div>
            ),
          }}
        />
      </>
    )
    expect(variantOf('New workflow')).toBe('default')
    expect(variantOf('Create workflow')).toBe('outline')
  })

  it('warns outside production when a filled action it cannot reach stays filled', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    function OwnButton() {
      return <Button>Create group</Button>
    }
    render(
      <>
        <Button>New group</Button>
        <EmptyState icon={Inbox} title="No groups yet" action={<OwnButton />} />
      </>
    )
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('One filled button per screen'))
  })
})
