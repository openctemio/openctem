/**
 * Validation issues and preview notes are worded from the server's stable code
 * and values in the reader's language; a code the catalog does not know shows
 * the server's English text.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { translate, type Dictionary } from '@/lib/i18n'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const dicts = vi.hoisted(() => ({
  active: {} as Record<string, string>,
  preview: vi.fn(),
}))

vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    locale: 'vi',
    t: (key: string, fallback?: string, vars?: Record<string, string | number>) =>
      translate(dicts.active as Dictionary, key, fallback, vars, 'vi'),
  }),
}))
vi.mock('../api/use-ticket-mapping-api', () => ({
  mappingApi: { preview: (...a: unknown[]) => dicts.preview(...a) },
}))

import { issueText } from '../lib/issue-text'
import { IssueList } from '../components/mapping-editor'
import { MappingPreview } from '../components/mapping-preview'
import { FieldMapper } from '../components/field-mapper'
import { WorkflowMapper } from '../components/workflow-mapper'
import type { CatalogView, MappingSpec, ValidationIssue } from '../types/ticket-mapping.types'

const CATALOG_VI: Record<string, string> = {
  'serverText.ticketmap.required_unmapped': 'Trường bắt buộc "{name}" chưa được ánh xạ.',
  'serverText.ticketmap.note_value_not_allowed':
    'Giá trị "{value}" không được phép: bỏ qua trường này.',
  'serverText.ticketmap.empty': 'Không có giá trị.',
  'serverText.ticketmap.status_missing':
    '{state} tới trạng thái {status} không có trong quy trình.',
}

const known: ValidationIssue = {
  severity: 'error',
  code: 'required_unmapped',
  row_id: 'r1',
  state: 'new',
  field_id: 'team',
  message: 'required field "Team" has no mapping',
  params: { name: 'Team' },
}
const unknownCode: ValidationIssue = {
  severity: 'warning',
  code: 'brand_new_rule',
  row_id: 'r1',
  message: 'a rule newer than this web',
  params: { name: 'x' },
}
const oldServer: ValidationIssue = {
  severity: 'info',
  code: 'required_unmapped',
  message: 'required field "Team" has no mapping',
}

const t = (key: string, fallback?: string, vars?: Record<string, string | number>) =>
  translate(CATALOG_VI as Dictionary, key, fallback, vars, 'vi')

describe('issueText', () => {
  it('words a known code from its values', () => {
    expect(issueText(t, 'vi', known)).toBe('Trường bắt buộc "Team" chưa được ánh xạ.')
  })
  it('keeps a value that looks like a placeholder as literal text', () => {
    const msg = issueText(t, 'vi', { ...known, params: { name: '{count}' } })
    expect(msg).toBe('Trường bắt buộc "{count}" chưa được ánh xạ.')
  })
  it('words from message_code when the code is shared, and from code without one', () => {
    const shared = { ...known, code: 'note', message_code: 'required_unmapped' }
    expect(issueText(t, 'vi', shared)).toBe('Trường bắt buộc "Team" chưa được ánh xạ.')
    expect(issueText(t, 'vi', { ...shared, message_code: 'future_sentence' })).toBe(known.message)
  })
  it('falls back to the server text for an unknown code', () => {
    expect(issueText(t, 'vi', unknownCode)).toBe('a rule newer than this web')
  })
  it('falls back when the catalog is empty', () => {
    const none = (k: string, f?: string, v?: Record<string, string | number>) =>
      translate({} as Dictionary, k, f, v, 'en')
    expect(
      issueText(none, 'en', { ...known, code: 'future_rule', message_code: 'future_rule' })
    ).toBe(known.message)
  })
})

describe('components', () => {
  beforeEach(() => {
    dicts.active = { ...CATALOG_VI }
    dicts.preview.mockReset()
  })

  it('the editor issue list shows the worded issue, or the English text without a code entry', () => {
    const { rerender } = render(<IssueList issues={[known, unknownCode]} />)
    expect(screen.getByText('Trường bắt buộc "Team" chưa được ánh xạ.')).toBeInTheDocument()
    expect(screen.getByText('a rule newer than this web')).toBeInTheDocument()
    dicts.active = {}
    const future = { ...known, code: 'future_rule', message_code: 'future_rule' }
    rerender(<IssueList issues={[future, { ...oldServer, code: 'future_rule' }]} />)
    expect(screen.getAllByText('required field "Team" has no mapping')).toHaveLength(2)
  })

  it('the preview words the not sent rows and the notes', async () => {
    dicts.preview.mockResolvedValue({
      fields: { description: 'x' },
      dropped: [
        { severity: 'warning', code: 'empty', field_id: 'summary', message: 'no value' },
        {
          severity: 'warning',
          code: 'future_drop',
          field_id: 'labels',
          message: 'because reasons',
        },
      ],
      notes: [
        {
          severity: 'info',
          code: 'note',
          message_code: 'note_value_not_allowed',
          field_id: 'priority',
          message: 'value Nope is not allowed: field left out',
          params: { value: 'Nope' },
        },
      ],
      issues: [],
      state: 'new',
    })
    const user = userEvent.setup({ delay: null })
    render(<MappingPreview profileId="p1" kind="finding" fields={[]} dirty={false} />)
    await user.type(screen.getByLabelText(/Finding ID|ID/), '123e4567-e89b-12d3-a456-426614174000')
    await user.click(screen.getByRole('button', { name: /Preview/ }))
    await waitFor(() =>
      expect(
        screen.getByText(/summary \(Không có giá trị\.\), labels \(because reasons\)/)
      ).toBeInTheDocument()
    )
    expect(
      screen.getByText(/priority: Giá trị "Nope" không được phép: bỏ qua trường này\./)
    ).toBeInTheDocument()
  })

  it('a field row shows the worded issue', () => {
    const catalog = {
      attributes: [
        {
          path: 'finding.title',
          kind: 'finding',
          type: 'text',
          tier: 'title_only',
          inbound: 'never',
        },
      ],
      filters: [],
      states: [],
      intents: [],
      presets: [],
      minimizations: [],
      transform_kinds: [],
    } as unknown as CatalogView
    const spec: MappingSpec = {
      minimization: 'summary',
      comments_out: false,
      comments_in: false,
      status: {},
      fields: [
        {
          id: 'r1',
          source: { kind: 'attr', attr: 'finding.title' },
          target: { field_id: 'team' },
          direction: 'out',
        } as unknown as MappingSpec['fields'][number],
      ],
    }
    render(
      <FieldMapper
        spec={spec}
        onChange={() => {}}
        catalog={catalog}
        fields={[
          {
            id: 'team',
            name: 'Team',
            required: true,
            has_default: false,
            schema: { type: 'string' },
          },
        ]}
        issues={[known]}
        readOnly
      />
    )
    expect(screen.getByText('Trường bắt buộc "Team" chưa được ánh xạ.')).toBeInTheDocument()
  })

  it('the status mapper words a state issue', () => {
    const catalog = {
      attributes: [],
      filters: [],
      states: ['new'],
      intents: [],
      presets: [],
      minimizations: [],
      transform_kinds: [],
    } as unknown as CatalogView
    render(
      <WorkflowMapper
        profileId="p1"
        kind="finding"
        spec={{
          minimization: 'summary',
          comments_out: false,
          comments_in: false,
          status: { outbound: { new: { status_id: '77' } } },
          fields: [],
        }}
        onChange={() => {}}
        catalog={catalog}
        workflow={{
          statuses: [{ id: '1', name: 'To Do', category: 'new' }],
          transitions: [],
          resolutions: [],
        }}
        issues={[
          {
            severity: 'error',
            code: 'status_missing',
            message_code: 'status_missing',
            state: 'new',
            message: 'new to status 77 is not in the workflow',
            params: { state: 'new', status: '77' },
          },
        ]}
        readOnly
        dirty={false}
      />
    )
    expect(screen.getByText('new tới trạng thái 77 không có trong quy trình.')).toBeInTheDocument()
  })
})
