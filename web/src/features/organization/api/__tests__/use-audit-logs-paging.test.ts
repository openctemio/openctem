/**
 * Audit-log paging contract.
 *
 * The API pages are 1-based (api/internal/infra/http/handler/audit_handler.go,
 * pagination.New clamps page<1 to 1 and Offset = (page-1)*per_page). Sending a
 * table pageIndex (0-based) as `page` showed the newest page twice and made
 * the oldest page unreachable. These tests pin the contract for all three
 * audit hooks and for the settings page's conversion.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook } from '@testing-library/react'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import useSWR from 'swr'

vi.mock('swr', () => ({
  default: vi.fn(() => ({ data: undefined, error: undefined, isLoading: false, mutate: vi.fn() })),
}))
vi.mock('@/lib/api/client', () => ({ fetcher: vi.fn() }))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1' } }),
}))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useTenantModules: () => ({ moduleIds: ['audit'], isLoading: false }),
}))

import {
  toAuditApiPage,
  getAuditLogsKey,
  useAuditLogs,
  useResourceAuditHistory,
  useUserAuditActivity,
} from '../use-audit-logs'

function lastKey(): string {
  const calls = vi.mocked(useSWR).mock.calls
  return calls[calls.length - 1][0] as string
}

function pageOf(url: string): string | null {
  return new URL(url, 'http://x').searchParams.get('page')
}

describe('audit-log paging is 1-based on the wire', () => {
  beforeEach(() => vi.mocked(useSWR).mockClear())

  it('converts a 0-based table pageIndex to the 1-based API page', () => {
    expect(toAuditApiPage(0)).toBe(1)
    expect(toAuditApiPage(1)).toBe(2)
    expect(toAuditApiPage(9)).toBe(10)
    expect(toAuditApiPage(-1)).toBe(1)
    expect(toAuditApiPage(Number.NaN)).toBe(1)
  })

  it('table pages 1 and 2 request different API pages (no duplicate newest page)', () => {
    const first = getAuditLogsKey({ page: toAuditApiPage(0), per_page: 20 })
    const second = getAuditLogsKey({ page: toAuditApiPage(1), per_page: 20 })
    expect(pageOf(first)).toBe('1')
    expect(pageOf(second)).toBe('2')
  })

  it('the last table page maps to the last API page (oldest rows reachable)', () => {
    // 45 rows at 20 per page = 3 pages; the table's last pageIndex is 2.
    expect(pageOf(getAuditLogsKey({ page: toAuditApiPage(2), per_page: 20 }))).toBe('3')
  })

  it('never sends page=0', () => {
    expect(pageOf(getAuditLogsKey({ page: 0 }))).toBe('1')
  })

  it('useAuditLogs passes the 1-based page through', () => {
    renderHook(() => useAuditLogs({ page: 2, per_page: 20 }))
    expect(pageOf(lastKey())).toBe('2')
  })

  it('useResourceAuditHistory defaults to page 1, not 0', () => {
    renderHook(() => useResourceAuditHistory('role', 'r1'))
    expect(pageOf(lastKey())).toBe('1')
    renderHook(() => useResourceAuditHistory('role', 'r1', 3))
    expect(pageOf(lastKey())).toBe('3')
  })

  it('useUserAuditActivity defaults to page 1, not 0', () => {
    renderHook(() => useUserAuditActivity('u1'))
    expect(pageOf(lastKey())).toBe('1')
    renderHook(() => useUserAuditActivity('u1', 0))
    expect(pageOf(lastKey())).toBe('1')
  })

  it('the settings audit-log page converts pageIndex with toAuditApiPage', () => {
    const src = readFileSync(
      join(process.cwd(), 'src/app/(dashboard)/settings/audit-log/page.tsx'),
      'utf8'
    )
    expect(src).toMatch(/page:\s*toAuditApiPage\(pagination\.pageIndex\)/)
    expect(src).not.toMatch(/page:\s*pagination\.pageIndex\b/)
  })
})
