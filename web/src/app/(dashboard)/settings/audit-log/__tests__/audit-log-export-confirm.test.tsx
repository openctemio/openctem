import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import AuditLogPage from '../page'
import en from '@/lib/i18n/dictionaries/en/auditLog.json'
import enConfirm from '@/lib/i18n/dictionaries/en/confirm.json'

const runExport = vi.fn().mockResolvedValue(undefined)

vi.mock('@/features/organization', async (orig) => ({
  ...(await orig<object>()),
  useAuditLogs: () => ({
    logs: [],
    total: 0,
    isLoading: false,
    isError: false,
    mutate: vi.fn(),
  }),
  useAuditStats: () => ({ stats: undefined, isLoading: false }),
  useAuditExport: () => ({ run: runExport, isExporting: false }),
}))
vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    t: (k: string) =>
      (en as Record<string, string>)[k] ?? (enConfirm as Record<string, string>)[k] ?? k,
    locale: 'en',
  }),
}))
vi.mock('@/lib/permissions', () => ({
  Permission: { AuditRead: 'audit:read' },
  useHasPermission: () => true,
}))
vi.mock('@/hooks/use-url-param', () => ({
  useUrlFilter: (_k: string, d: string) => [d, vi.fn()],
}))
vi.mock('@/hooks/use-list-params', () => ({
  useListParams: () => ({
    pagination: { pageIndex: 0, pageSize: 20 },
    setPagination: vi.fn(),
    sorting: [],
    setSorting: vi.fn(),
  }),
}))

describe('Audit log export confirmation', () => {
  beforeEach(() => vi.clearAllMocks())

  it('names the PII in the file and exports only after confirming', async () => {
    const user = userEvent.setup()
    render(<AuditLogPage />)
    await user.click(screen.getByRole('button', { name: 'Export' }))
    await user.click(await screen.findByRole('menuitem', { name: 'CSV' }))

    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent("members' emails and IP addresses")
    expect(dialog).toHaveTextContent('verify')
    expect(runExport).not.toHaveBeenCalled()

    await user.click(screen.getByRole('button', { name: 'Export CSV' }))
    await waitFor(() => expect(runExport).toHaveBeenCalledWith('csv'))
  })

  it('does not export when the dialog is cancelled', async () => {
    const user = userEvent.setup()
    render(<AuditLogPage />)
    await user.click(screen.getByRole('button', { name: 'Export' }))
    await user.click(await screen.findByRole('menuitem', { name: 'JSON lines' }))
    expect(await screen.findByRole('button', { name: 'Export JSON lines' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(runExport).not.toHaveBeenCalled()
  })
})
