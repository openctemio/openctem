import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'
import { useState, type ReactNode } from 'react'

const api = vi.hoisted(() => ({
  preview: vi.fn(),
  paste: vi.fn(),
}))

vi.mock('../../../api/use-group-rule-api', () => ({
  previewGroupRule: (...a: unknown[]) => api.preview(...a),
  pasteIntoGroup: (...a: unknown[]) => api.paste(...a),
  invalidateGroupMembership: vi.fn(),
  setGroupRule: vi.fn(),
  useGroupHistoryApi: () => ({ data: undefined, isLoading: false }),
}))
vi.mock('@/features/asset-types/api/use-asset-type-registry', () => ({
  useAssetTypeRegistry: () => ({
    registry: {
      types: [
        { type: 'domain', label: 'Domain' },
        { type: 'host', label: 'Host' },
      ],
    },
  }),
}))
vi.mock('@/features/scope/api/use-scope-api', () => ({
  useScopeTargetsApi: () => ({ data: { data: [{ id: 's1', pattern: '*.example.com' }] } }),
}))
vi.mock('@/lib/permissions', () => ({
  usePermissions: () => ({ can: () => true }),
  Permission: { AssetsWrite: 'assets:write', AssetGroupsRead: 'assets:groups:read' },
}))
vi.mock('../../create-group/add-assets-step', () => ({
  AddAssetsStep: () => <div data-testid="pick-step" />,
}))

import { MembersStep } from '../members-step'
import { DEFAULT_CREATE_GROUP_FORM, type CreateGroupFormData } from '../../create-group/types'
import { PasteEditor } from '../paste-editor'
import { ImpactNotice } from '../impact-notice'
import { RuleStatusNote } from '../rule-status-note'

function wrap(ui: ReactNode) {
  return <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>
}

function Harness({ initial }: { initial?: Partial<CreateGroupFormData> }) {
  // A tiny controlled host for the step.
  const [data, setData] = useState<CreateGroupFormData>({
    ...DEFAULT_CREATE_GROUP_FORM,
    ...initial,
  })
  return (
    <MembersStep
      data={data}
      onChange={(patch) => setData((d) => ({ ...d, ...patch }))}
      ungroupedAssets={[]}
    />
  )
}

beforeEach(() => {
  api.preview.mockReset()
  api.paste.mockReset()
  api.preview.mockResolvedValue({
    count: 2,
    cap: 50000,
    over_cap: false,
    sample: [{ id: 'a1', name: 'www.example.com', type: 'domain' }],
    would_join: 0,
    would_leave: 0,
  })
})

describe('Members step', () => {
  it('has the Rule, Pick and Paste tabs', () => {
    render(wrap(<Harness />))
    expect(screen.getByRole('tab', { name: /rule/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /pick/i })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /paste/i })).toBeInTheDocument()
  })

  it('previews the rule the domains describe, as the document the API takes', async () => {
    render(wrap(<Harness />))
    expect(screen.getByTestId('rule-preview-empty')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Domains'), { target: { value: '*.example.com' } })
    await waitFor(() => expect(api.preview).toHaveBeenCalled(), { timeout: 3000 })
    const [doc] = api.preview.mock.calls[api.preview.mock.calls.length - 1]
    expect(doc).toEqual({
      v: 1,
      filter: {},
      domains: [{ name: '*.example.com', subdomains: true }],
    })
    await waitFor(() =>
      expect(screen.getByTestId('rule-preview-count')).toHaveTextContent('2 assets match')
    )
    expect(screen.getByText('www.example.com')).toBeInTheDocument()
  })

  it('does not ask for a preview of an invalid domain', async () => {
    render(wrap(<Harness />))
    fireEvent.change(screen.getByLabelText('Domains'), { target: { value: 'http://evil' } })
    expect(await screen.findByTestId('rule-preview-blocked')).toHaveTextContent('http://evil')
    expect(api.preview).not.toHaveBeenCalled()
  })

  it('warns when the rule matches more than a group may hold', async () => {
    api.preview.mockResolvedValue({
      count: 50001,
      cap: 50000,
      over_cap: true,
      sample: [],
      would_join: 0,
      would_leave: 0,
    })
    render(wrap(<Harness />))
    fireEvent.change(screen.getByLabelText('Domains'), { target: { value: 'example.com' } })
    expect(
      await screen.findByText(/More than 50,000 assets match/, {}, { timeout: 3000 })
    ).toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent(/at most 50,000/)
  })
})

describe('Paste editor', () => {
  it('shows a dry run for a group that exists, with the rejected lines and why', async () => {
    api.paste.mockResolvedValue({
      lines: 3,
      matched: 1,
      added: 0,
      created: 0,
      candidates: 0,
      skipped: 0,
      not_found: 1,
      missing_sample: [{ line: 2, value: 'new.example.com', kind: 'domain' }],
      rejected: [{ line: 3, value: 'javascript:alert(1)', reason: 'not_a_name_address_or_url' }],
    })
    render(
      wrap(
        <PasteEditor
          text={'www.example.com\nnew.example.com\njavascript:alert(1)'}
          onTextChange={() => {}}
          createMissing={false}
          onCreateMissingChange={() => {}}
          groupId="g1"
        />
      )
    )
    await waitFor(() => expect(api.paste).toHaveBeenCalled(), { timeout: 3000 })
    expect(api.paste.mock.calls[0]).toEqual([
      'g1',
      { text: 'www.example.com\nnew.example.com\njavascript:alert(1)', dryRun: true },
    ])
    const summary = await screen.findByTestId('paste-summary')
    expect(summary).toHaveTextContent('1 found')
    expect(summary).toHaveTextContent('1 not found')
    expect(summary).toHaveTextContent('1 rejected')
    expect(screen.getByText(/Not a name, address, range or URL/)).toBeInTheDocument()
  })

  it('refuses a list over the line cap without asking the server', () => {
    render(
      wrap(
        <PasteEditor
          text={'a.example.com\n'.repeat(10001)}
          onTextChange={() => {}}
          createMissing={false}
          onCreateMissingChange={() => {}}
          groupId="g1"
        />
      )
    )
    expect(screen.getByText(/at most 10,000 lines/)).toBeInTheDocument()
    expect(api.paste).not.toHaveBeenCalled()
  })

  it('in the wizard it says the list is matched after the group exists', () => {
    render(
      wrap(
        <PasteEditor
          text=""
          onTextChange={() => {}}
          createMissing={false}
          onCreateMissingChange={() => {}}
        />
      )
    )
    expect(screen.getByText(/matched when the group is created/)).toBeInTheDocument()
  })
})

describe('Impact notice and rule status', () => {
  it('names the teams and scans a widening change reaches, and the privileged team', () => {
    render(
      <ImpactNotice
        impact={{
          widens: true,
          would_join: 12,
          teams: [{ id: 't1', name: 'Payments', privileged: true }],
          scans: [{ id: 's1', name: 'Nightly' }],
          privileged_team: true,
        }}
      />
    )
    const n = screen.getByTestId('group-impact-notice')
    expect(n).toHaveTextContent('12 more assets')
    expect(n).toHaveTextContent('Payments')
    expect(n).toHaveTextContent('Nightly')
    expect(n).toHaveTextContent(/only the owner/)
  })

  it('shows nothing for a group nobody uses', () => {
    const { container } = render(
      <ImpactNotice
        impact={{ widens: false, would_join: 3, teams: [], scans: [], privileged_team: false }}
      />
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('tells when a rule is paused or over the cap', () => {
    const base = { document: { v: 1 as const, filter: {} }, excluded: 0, cap: 50000 }
    const { rerender } = render(<RuleStatusNote rule={{ ...base, status: 'paused' }} />)
    expect(screen.getByTestId('rule-status-note')).toHaveTextContent(/paused/)
    rerender(<RuleStatusNote rule={{ ...base, status: 'over_cap' }} />)
    expect(screen.getByTestId('rule-status-note')).toHaveTextContent(/more than 50,000/)
    rerender(<RuleStatusNote rule={{ ...base, status: 'ok', excluded: 2 }} />)
    expect(screen.getByTestId('rule-status-note')).toHaveTextContent(
      /2 assets were taken out by hand/
    )
    rerender(<RuleStatusNote rule={{ ...base, status: 'ok' }} />)
    expect(screen.queryByTestId('rule-status-note')).toBeNull()
  })
})
