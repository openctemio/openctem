import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { VexImportResult, VexStatement } from '../../api/vex'

const granted = new Set<string>()
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: (p: string) => granted.has(p) }),
}))

const statements: { data: { data: VexStatement[] } | undefined } = { data: undefined }
const importVexDocument = vi.fn()
const deleteVexStatement = vi.fn()
vi.mock('../../api/vex', async (orig) => ({
  ...(await orig<typeof import('../../api/vex')>()),
  useVexStatements: () => ({
    data: statements.data,
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
  importVexDocument: (...a: unknown[]) => importVexDocument(...a),
  deleteVexStatement: (...a: unknown[]) => deleteVexStatement(...a),
}))
vi.mock('@/features/assets/hooks/use-assets', () => ({
  useAssets: () => ({
    assets: [{ id: 'a1', name: 'shop-repo', type: 'repository' }],
    isLoading: false,
  }),
}))

import { initialVexForm, validateVexForm, vexFormPayload } from '../vex-statement-dialog'
import { VexStatementsPanel } from '../vex-statements-panel'
import { MAX_VEX_BYTES, readVexFile, VexImportDialog } from '../vex-import-dialog'

const stmt: VexStatement = {
  id: 's1',
  vuln_id: 'CVE-2021-23337',
  product_id: 'p1',
  versions: ['4.17.20'],
  status: 'not_affected',
  justification: 'vulnerable_code_not_in_execute_path',
  origin: 'manual',
  expired: false,
  created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-01T00:00:00Z',
}

beforeEach(() => {
  granted.clear()
  statements.data = undefined
  importVexDocument.mockReset()
  deleteVexStatement.mockReset()
})

describe('VEX statement form', () => {
  it('needs a justification or an impact statement for not affected', () => {
    const f = { ...initialVexForm(null), vulnId: 'CVE-2024-3094' }
    expect(validateVexForm(f, true)).toBe('components.vex.error.why')
    expect(validateVexForm({ ...f, justification: 'component_not_present' }, true)).toBeNull()
    expect(validateVexForm({ ...f, impact: 'not loaded' }, true)).toBeNull()
    expect(validateVexForm({ ...f, status: 'affected' }, true)).toBeNull()
  })

  it('checks the vulnerability id, versions, range and review date', () => {
    const f = { ...initialVexForm(null), vulnId: 'CVE-2024-3094', status: 'affected' as const }
    expect(validateVexForm({ ...f, vulnId: 'x' }, true)).toBe('components.vex.error.vulnId')
    expect(validateVexForm({ ...f, versionMode: 'list', versions: ' , ' }, true)).toBe(
      'components.vex.error.versions'
    )
    expect(validateVexForm({ ...f, versionMode: 'range', range: '1.0' }, true)).toBe(
      'components.vex.error.range'
    )
    expect(validateVexForm({ ...f, expiresAt: '2000-01-01' }, true)).toBe(
      'components.vex.error.expiry'
    )
  })

  it('sends the subject only on create, and clears an expiry that was removed', () => {
    const f = {
      ...initialVexForm(null),
      vulnId: ' CVE-2024-3094 ',
      justification: 'component_not_present',
      versionMode: 'list' as const,
      versions: '1.0, 1.1 1.0',
    }
    expect(vexFormPayload(f, 'p1', { id: 'a1', name: 'shop-repo' }, null)).toMatchObject({
      vuln_id: 'CVE-2024-3094',
      product_id: 'p1',
      asset_id: 'a1',
      versions: ['1.0', '1.1'],
      version_range: '',
      status: 'not_affected',
    })
    const editing = { ...stmt, expires_at: '2027-01-01T00:00:00Z' }
    const body = vexFormPayload({ ...initialVexForm(editing), expiresAt: '' }, 'p1', null, editing)
    expect(body.vuln_id).toBeUndefined()
    expect(body.product_id).toBeUndefined()
    expect(body.clear_expiry).toBe(true)
  })
})

describe('VEX statements panel', () => {
  it('lists the statements and hides write actions without findings:approve', () => {
    granted.add('assets:components:read')
    statements.data = { data: [stmt] }
    render(<VexStatementsPanel productId="p1" />)
    expect(screen.getByText('CVE-2021-23337')).toBeTruthy()
    expect(screen.getByText('Not affected')).toBeTruthy()
    expect(screen.getByText('Vulnerable code not in execute path')).toBeTruthy()
    expect(screen.getByText('Every asset')).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'New statement' })).toBeNull()
    expect(screen.queryByRole('button', { name: /Delete statement/ })).toBeNull()
  })

  it('offers create, edit and delete with findings:approve', async () => {
    granted.add('findings:approve')
    statements.data = { data: [stmt] }
    deleteVexStatement.mockResolvedValue({ applied: { matched: 0, closed: 0, reopened: 2 } })
    render(<VexStatementsPanel productId="p1" />)
    expect(screen.getByRole('button', { name: 'New statement' })).toBeTruthy()
    await userEvent.click(screen.getByRole('button', { name: 'Delete statement CVE-2021-23337' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(deleteVexStatement).toHaveBeenCalledWith('s1'))
  })

  it('says what to do when there is no statement', () => {
    statements.data = { data: [] }
    render(<VexStatementsPanel productId="p1" />)
    expect(screen.getByText(/No statements yet/)).toBeTruthy()
  })
})

describe('VEX import', () => {
  const preview: VexImportResult = {
    format: 'openvex',
    dry_run: true,
    statements: 1,
    created: 1,
    updated: 0,
    unchanged: 0,
    skipped_total: 1,
    skipped: [
      { vuln_id: 'CVE-2021-1000', purl: 'pkg:npm/x@1', reason: 'package not in the inventory' },
    ],
    issues: [],
    items: [
      {
        vuln_id: 'CVE-2021-23337',
        purl: 'pkg:npm/lodash@4.17.20',
        product_id: 'p1',
        versions: ['4.17.20'],
        status: 'not_affected',
        action: 'create',
      },
    ],
    applied: { matched: 0, closed: 0, reopened: 0 },
  }

  it('previews first, then imports for every asset', async () => {
    importVexDocument.mockResolvedValueOnce(preview).mockResolvedValueOnce({
      ...preview,
      dry_run: false,
      applied: { matched: 2, closed: 2, reopened: 0 },
    })
    const onImported = vi.fn()
    render(<VexImportDialog open onOpenChange={() => {}} onImported={onImported} />)
    await userEvent.upload(
      screen.getByLabelText('VEX document'),
      new File(['{"statements":[]}'], 'vex.json', { type: 'application/json' })
    )
    await userEvent.click(screen.getByRole('button', { name: 'Preview' }))
    await waitFor(() =>
      expect(importVexDocument).toHaveBeenCalledWith({ statements: [] }, null, true)
    )
    expect(await screen.findByText('package not in the inventory')).toBeTruthy()
    await userEvent.click(screen.getByRole('button', { name: 'Import 1 statements' }))
    await waitFor(() =>
      expect(importVexDocument).toHaveBeenLastCalledWith({ statements: [] }, null, false)
    )
    expect(onImported).toHaveBeenCalled()
    expect(await screen.findByText('2 findings closed, 0 reopened.')).toBeTruthy()
  })

  it('refuses a file over the size limit without reading it', async () => {
    const text = vi.fn()
    await expect(readVexFile({ size: MAX_VEX_BYTES + 1, text } as unknown as File)).rejects.toThrow(
      'too_large'
    )
    expect(text).not.toHaveBeenCalled()
  })
})
