/**
 * Preview warnings are worded from the server's code and counts, and the
 * starter templates from their stable key; unknown codes and keys show the
 * server's English text.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { translate, type Dictionary } from '@/lib/i18n'
import type { PreviewResult } from '../types/import-mapping.types'

const state = vi.hoisted(() => ({
  dict: {} as Record<string, string>,
  preview: vi.fn(),
  templates: [] as unknown[],
}))

vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    locale: 'vi',
    t: (key: string, fallback?: string, vars?: Record<string, string | number>) =>
      translate(state.dict as Dictionary, key, fallback, vars, 'vi'),
  }),
}))
vi.mock('@/lib/permissions', () => ({
  Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  Permission: { IntegrationsRead: 'integrations:read', IntegrationsManage: 'integrations:manage' },
  usePermissions: () => ({ can: () => true }),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/components/link', () => ({
  default: ({ children, href }: { children: React.ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
}))
vi.mock('next/navigation', () => ({ useRouter: () => ({ replace: vi.fn(), push: vi.fn() }) }))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('../api/import-mappings-api', async (importOriginal) => {
  const real = await importOriginal<typeof import('../api/import-mappings-api')>()
  return {
    ...real,
    previewMapping: (...a: unknown[]) => state.preview(...a),
    useImportMapping: () => ({
      data: undefined,
      error: undefined,
      isLoading: false,
      mutate: vi.fn(),
    }),
    useImportMappingTemplates: () => ({ data: { items: state.templates }, isLoading: false }),
  }
})

import { PreviewPane } from '../components/preview-pane'
import { ImportMappingEditor } from '../components/import-mapping-editor'

const DOC = {
  apiVersion: 'openctem.io/mapping/v2',
  source: 'csv',
  identity: ['title'],
  records: [],
}

function result(warnings: PreviewResult['warnings']): PreviewResult {
  return {
    items: [],
    stats: { records: 4, findings: 4, assets: 0, skipped: 0, truncated: false },
    warnings,
    issues: [],
    fields: [],
    unmapped: [],
  }
}

async function showWarnings(warnings: PreviewResult['warnings']) {
  state.preview.mockResolvedValue(result(warnings))
  render(
    <PreviewPane
      document={DOC as never}
      file={new File(['a'], 'a.csv')}
      canPreview
      onFields={() => {}}
    />
  )
  await screen.findByText(/4 bản ghi|4 records/)
}

const warnings: PreviewResult['warnings'] = [
  {
    code: 'identity_collision',
    message: '2 of 4 findings share an identity',
    params: { count: 2, total: 4 },
  },
  {
    code: 'unmapped_fields',
    message: '3 fields of the sample are not mapped',
    params: { count: 3 },
  },
  { code: 'future_code', message: 'a warning newer than this web' },
]

describe('preview warnings', () => {
  beforeEach(() => {
    state.preview.mockReset()
  })

  it('words a warning from its code and counts', async () => {
    state.dict = {
      'serverText.import.warning.identity_collision':
        'Có {count} trên {total} phát hiện trùng định danh.',
      'serverText.import.warning.unmapped_fields': '{count, plural, other {# trường chưa ánh xạ}}',
      'importMappings.preview.stats': '{records} bản ghi',
    }
    await showWarnings(warnings)
    expect(screen.getByText('Có 2 trên 4 phát hiện trùng định danh.')).toBeInTheDocument()
    expect(screen.getByText('3 trường chưa ánh xạ')).toBeInTheDocument()
    expect(screen.getByText('a warning newer than this web')).toBeInTheDocument()
  })

  it('shows the server text when the catalog has no entry', async () => {
    state.dict = { 'importMappings.preview.stats': '{records} bản ghi' }
    await showWarnings([
      { code: 'future_a', message: 'first newer warning', params: { count: 2 } },
      { code: 'future_b', message: 'second newer warning' },
    ])
    expect(screen.getByText('first newer warning')).toBeInTheDocument()
    expect(screen.getByText('second newer warning')).toBeInTheDocument()
  })
})

describe('starter templates', () => {
  const tpl = (key: string) => ({
    key,
    name: `Server name ${key}`,
    description: `Server notes ${key}`,
    source: 'csv',
    mapping: DOC,
  })

  it('words the name and notes from the template key, with the server text as fallback', () => {
    state.templates = [tpl('generic-csv'), tpl('brand-new')]
    state.dict = {
      'importMappings.template.generic-csv.name': 'CSV phát hiện chung',
      'importMappings.template.generic-csv.notes': 'Mẫu khởi đầu theo dòng',
    }
    render(<ImportMappingEditor />)
    expect(screen.getByText('CSV phát hiện chung')).toBeInTheDocument()
    expect(screen.getByText('Mẫu khởi đầu theo dòng')).toBeInTheDocument()
    expect(screen.getByText('Server name brand-new')).toBeInTheDocument()
    expect(screen.getByText('Server notes brand-new')).toBeInTheDocument()
  })
})
