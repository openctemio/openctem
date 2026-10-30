/**
 * The import mapping editor: the identity-change confirmation (a 409 from the
 * API, then the same version resent with confirm_identity_change), and the
 * permission gating of every write (the API stays the authority).
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { ApiClientError } from '@/lib/api/error-handler'
import type { ImportMappingDetail } from '../types/import-mapping.types'

let perms = new Set<string>()
const createVersion = vi.fn()
const removeMapping = vi.fn()
const replace = vi.fn()
const push = vi.fn()
const mutate = vi.fn()

vi.mock('@/lib/permissions', () => ({
  Can: ({ permission, children }: { permission: string; children: ReactNode }) =>
    perms.has(permission) ? <>{children}</> : null,
  Permission: {
    IntegrationsRead: 'integrations:read',
    IntegrationsManage: 'integrations:manage',
  },
  usePermissions: () => ({ can: (p: string) => perms.has(p) }),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/components/link', () => ({
  default: ({ children, href }: { children: ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
}))
vi.mock('next/navigation', () => ({ useRouter: () => ({ replace, push }) }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const detail: ImportMappingDetail = {
  mapping: {
    id: 'm1',
    name: 'vendor-csv',
    description: 'Vendor export',
    source: 'csv',
    latest_version: 2,
    created_at: '2026-10-01T00:00:00Z',
    updated_at: '2026-10-02T00:00:00Z',
  },
  version: {
    version: 2,
    digest: 'sha256:abc',
    identity: ['title'],
    identity_changed: false,
    note: '',
    created_at: '2026-10-02T00:00:00Z',
    mapping: {
      apiVersion: 'openctem.io/mapping/v1',
      source: 'csv',
      csv: { delimiter: 'auto' },
      identity: ['title'],
      records: [
        {
          kind: 'finding',
          set: { title: '/title', severity: '/severity', rule_id: '/rule' },
        },
      ],
    },
  },
  versions: [
    {
      version: 2,
      digest: 'sha256:abc',
      identity: ['title'],
      identity_changed: false,
      note: '',
      created_at: '2026-10-02T00:00:00Z',
    },
  ],
}

vi.mock('../api/import-mappings-api', async (importOriginal) => {
  const real = await importOriginal<typeof import('../api/import-mappings-api')>()
  return {
    ...real,
    useImportMapping: () => ({ data: detail, error: undefined, isLoading: false, mutate }),
    useImportMappings: () => ({
      data: { items: [detail.mapping] },
      error: undefined,
      isLoading: false,
      mutate,
    }),
    useImportMappingTemplates: () => ({ data: { items: [] }, isLoading: false }),
    invalidateImportMappings: vi.fn(async () => undefined),
    importMappingsApi: {
      ...real.importMappingsApi,
      createVersion: (...a: unknown[]) => createVersion(...a),
      remove: (...a: unknown[]) => removeMapping(...a),
    },
  }
})

import { ImportMappingEditor } from '../components/import-mapping-editor'
import { ImportMappingListView } from '../components/import-mapping-list-view'

function identityConflict() {
  return new ApiClientError('identity changed', 'identity_change_unconfirmed', 409, {
    previous_identity: ['title'],
    identity: ['title', 'rule_id'],
  })
}

async function addRuleIdToIdentityAndSave(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('checkbox', { name: 'Use rule_id to identify a finding' }))
  await user.click(screen.getByRole('button', { name: /Save as new version/ }))
  await user.type(screen.getByLabelText('Version note'), 'add rule')
  await user.click(screen.getByRole('button', { name: 'Save version' }))
}

describe('identity change confirmation', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    perms = new Set(['integrations:read', 'integrations:manage'])
  })

  it('asks before saving a version that identifies findings differently, then resends it', async () => {
    createVersion.mockRejectedValueOnce(identityConflict()).mockResolvedValueOnce({})
    const user = userEvent.setup()
    render(<ImportMappingEditor id="m1" />)
    await addRuleIdToIdentityAndSave(user)

    expect(await screen.findByText('Change how findings are identified?')).toBeInTheDocument()
    expect(screen.getByText(/refingerprint tool/)).toBeInTheDocument()
    expect(createVersion).toHaveBeenCalledTimes(1)
    const [id, first] = createVersion.mock.calls[0]
    expect(id).toBe('m1')
    expect(first.confirm_identity_change).toBeUndefined()
    expect(first.mapping.identity).toEqual(['title', 'rule_id'])

    await user.click(screen.getByRole('button', { name: 'Save with the new identity' }))
    await waitFor(() => expect(createVersion).toHaveBeenCalledTimes(2))
    const second = createVersion.mock.calls[1][1]
    expect(second).toMatchObject({ note: 'add rule', confirm_identity_change: true })
    expect(second.mapping).toEqual(first.mapping)
    await waitFor(() => expect(mutate).toHaveBeenCalled())
  })

  it('sends nothing more when the person cancels', async () => {
    createVersion.mockRejectedValueOnce(identityConflict())
    const user = userEvent.setup()
    render(<ImportMappingEditor id="m1" />)
    await addRuleIdToIdentityAndSave(user)
    await screen.findByText('Change how findings are identified?')
    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() =>
      expect(screen.queryByText('Change how findings are identified?')).toBeNull()
    )
    expect(createVersion).toHaveBeenCalledTimes(1)
  })
})

describe('delete confirmation', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    perms = new Set(['integrations:read', 'integrations:manage'])
  })

  it('deletes only after the mapping name is typed', async () => {
    removeMapping.mockResolvedValue(undefined)
    const user = userEvent.setup()
    render(<ImportMappingEditor id="m1" />)
    await user.click(screen.getByRole('button', { name: /Delete/ }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Delete the mapping "vendor-csv"?')
    const confirm = within(dialog).getByRole('button', { name: 'Delete mapping' })
    expect(confirm).toBeDisabled()
    await user.type(within(dialog).getByRole('textbox'), 'vendor-csv')
    await user.click(confirm)
    await waitFor(() => expect(removeMapping).toHaveBeenCalledWith('m1'))
  })
})

describe('permission gating', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('a reader sees the mapping but no way to change it, and no preview', () => {
    perms = new Set(['integrations:read'])
    render(<ImportMappingEditor id="m1" />)
    expect(screen.getByRole('heading', { name: 'vendor-csv' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Save as new version/ })).toBeNull()
    expect(screen.queryByRole('button', { name: /Rename/ })).toBeNull()
    expect(screen.queryByRole('button', { name: /Delete/ })).toBeNull()
    expect(screen.queryByRole('button', { name: /Check/ })).toBeNull()
    expect(screen.queryByRole('button', { name: /Add a field/ })).toBeNull()
    expect(screen.getByRole('checkbox', { name: 'Use title to identify a finding' })).toBeDisabled()
    expect(screen.getByLabelText('Sample file')).toBeDisabled()
    expect(screen.getByText(/needs the permission to manage integrations/)).toBeInTheDocument()
  })

  it('a manager gets every action', () => {
    perms = new Set(['integrations:read', 'integrations:manage'])
    render(<ImportMappingEditor id="m1" />)
    expect(screen.getByRole('button', { name: /Save as new version/ })).toBeDisabled()
    expect(screen.getByRole('button', { name: /Rename/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Delete/ })).toBeInTheDocument()
    expect(screen.getByLabelText('Sample file')).toBeEnabled()
  })

  it('a reader cannot start a new mapping', () => {
    perms = new Set(['integrations:read'])
    render(<ImportMappingEditor />)
    expect(screen.getByText(/Creating a mapping needs the permission/)).toBeInTheDocument()
    expect(screen.queryByText('Blank mapping')).toBeNull()
  })

  it('the list offers New mapping only to managers', () => {
    perms = new Set(['integrations:read'])
    const { unmount } = render(<ImportMappingListView />)
    expect(screen.getByText('vendor-csv')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /New mapping/ })).toBeNull()
    unmount()
    perms = new Set(['integrations:read', 'integrations:manage'])
    render(<ImportMappingListView />)
    expect(screen.getByRole('link', { name: /New mapping/ })).toHaveAttribute(
      'href',
      '/settings/integrations/import-mappings/new'
    )
  })
})
