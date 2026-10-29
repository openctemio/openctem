/**
 * ImportResultsDialog: preview before import, the knowledge base sent before
 * the file, per-file counts, problems with line numbers, refusals, and every
 * file-supplied value rendered as text.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ImportResultsDialog } from '../import-results-dialog'

const fetchMock = vi.fn()
vi.mock('@/lib/api/client', () => ({
  csrfFetch: (...a: unknown[]) => fetchMock(...a),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
// Saved import mappings offered as formats (features/import-mappings).
let mappingItems: { id: string; name: string }[] = []
let perms = new Set<string>()
vi.mock('@/features/import-mappings/api/import-mappings-api', () => ({
  useImportMappings: (enabled: boolean) => ({
    data: enabled ? { items: mappingItems } : undefined,
  }),
}))
vi.mock('@/lib/permissions', () => ({
  Permission: { IntegrationsRead: 'integrations:read', AssetsImport: 'assets:import' },
  useHasAnyPermission: (...p: string[]) => p.some((x) => perms.has(x)),
}))
// The recent-imports list fetches on its own; receipt-summary.test.tsx covers it.
vi.mock('../receipt-summary', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../receipt-summary')>()),
  RecentImports: () => null,
}))

function jsonResponse(status: number, body: unknown) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  }
}

const previewBody = {
  session_id: 's',
  dry_run: true,
  vex_mode: 'dry_run',
  vex_can_close: false,
  supported_formats: ['nessus'],
  files: [
    {
      name: '<img src=x onerror=alert(1)>.nessus',
      format: 'nessus',
      stats: {
        records: 3,
        assets: 2,
        findings: 3,
        components: 0,
        statements: 0,
        skipped: 1,
        by_severity: { high: 2, info: 1 },
      },
      issues: [
        { line: 12, path: '/NessusClientData_v2/Report/ReportHost', message: 'host skipped' },
      ],
      unmapped: ['/NessusClientData_v2/Report/ReportHost/ReportItem/new_field'],
    },
  ],
}

async function chooseFile(name = 'scan.nessus') {
  const input = screen.getByLabelText('File') as HTMLInputElement
  await userEvent.upload(input, new File(['<NessusClientData_v2/>'], name, { type: 'text/xml' }))
}

describe('ImportResultsDialog', () => {
  beforeEach(() => {
    fetchMock.mockReset()
    mappingItems = []
    perms = new Set()
  })

  it('offers no format choice without saved mappings or without a permission to list them', () => {
    const { unmount } = render(<ImportResultsDialog open onOpenChange={vi.fn()} />)
    expect(screen.queryByLabelText('Format')).toBeNull()
    unmount()
    mappingItems = [{ id: 'm1', name: 'vendor-csv' }]
    render(<ImportResultsDialog open onOpenChange={vi.fn()} />)
    expect(screen.queryByLabelText('Format')).toBeNull()
  })

  it('imports with a saved mapping as the format and drops the Qualys knowledge base', async () => {
    // Radix Select scrolls the chosen option into view; jsdom lacks it.
    Element.prototype.scrollIntoView ??= () => {}
    mappingItems = [{ id: 'm1', name: 'vendor-csv' }]
    perms = new Set(['assets:import'])
    fetchMock.mockResolvedValueOnce(jsonResponse(200, previewBody))
    const user = userEvent.setup()
    render(<ImportResultsDialog open onOpenChange={vi.fn()} />)
    expect(screen.getByLabelText(/Qualys KnowledgeBase/)).toBeInTheDocument()
    await user.click(screen.getByLabelText('Format'))
    await user.click(screen.getByRole('option', { name: 'Import mapping: vendor-csv' }))
    expect(screen.queryByLabelText(/Qualys KnowledgeBase/)).toBeNull()
    await chooseFile('export.csv')
    await user.click(screen.getByRole('button', { name: /Preview/ }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    expect(fetchMock.mock.calls[0][0]).toBe(
      '/api/v1/findings/imports?dry_run=true&format=mapping%3Avendor-csv'
    )
  })

  it('sends the minimum severity a caller sets (the scanners page skips info)', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, previewBody))
    render(<ImportResultsDialog open onOpenChange={vi.fn()} minSeverity="low" />)
    await chooseFile()
    await userEvent.click(screen.getByRole('button', { name: /Preview/ }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    expect(fetchMock.mock.calls[0][0]).toBe(
      '/api/v1/findings/imports?dry_run=true&min_severity=low'
    )
  })

  it('previews first and writes nothing until Import', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, previewBody))
    const onImported = vi.fn()
    render(<ImportResultsDialog open onOpenChange={vi.fn()} onImported={onImported} />)
    const importButton = screen.getByRole('button', { name: /^Import$/ })
    expect(importButton).toBeDisabled()
    await chooseFile()
    await userEvent.click(screen.getByRole('button', { name: /Preview/ }))

    await waitFor(() => expect(screen.getByTestId('import-summary')).toBeInTheDocument())
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe('/api/v1/findings/imports?dry_run=true')
    expect((init as RequestInit).method).toBe('POST')
    expect(screen.getByText('Nessus (.nessus)')).toBeInTheDocument()
    expect(screen.getByText('high: 2')).toBeInTheDocument()
    expect(screen.getByText('line 12: host skipped')).toBeInTheDocument()
    expect(screen.getByText(/1 source fields not recognized/)).toBeInTheDocument()
    expect(onImported).not.toHaveBeenCalled()
    // A file name from the upload is text, never markup.
    expect(screen.getByText('<img src=x onerror=alert(1)>.nessus')).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull()

    // A committed upload is stored (202), then its result is read once the
    // server's worker imported it.
    fetchMock.mockResolvedValueOnce(
      jsonResponse(202, {
        ...previewBody,
        dry_run: false,
        receipt_id: 'r1',
        status: 'queued',
        files: [],
      })
    )
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, {
        receipt_id: 'r1',
        status: 'applied',
        receipt: {
          id: 'r1',
          status: 'completed',
          source: { kind: 'upload', ref: 'r1' },
          coverage: { type: 'partial' },
          counts: {
            created: 2,
            updated: 0,
            reactivated: 0,
            closed: 0,
            untouched: null,
            skipped: 0,
            failed: 0,
          },
        },
        files: [
          {
            ...previewBody.files[0],
            ingest: {
              findings_created: 2,
              findings_updated: 0,
              findings_skipped: 0,
              assets_created: 2,
              assets_updated: 0,
              assets_skipped_out_of_scope: 0,
              components_created: 0,
              components_updated: 0,
            },
          },
        ],
      })
    )
    await userEvent.click(screen.getByRole('button', { name: /^Import$/ }))
    await waitFor(() => expect(onImported).toHaveBeenCalled())
    expect(fetchMock.mock.calls[1][0]).toBe('/api/v1/findings/imports')
    expect(fetchMock.mock.calls[2][0]).toBe('/api/v1/findings/imports/r1/result?wait=10')
    expect(screen.getByText(/2 findings created/)).toBeInTheDocument()
    // The upload's receipt: partial coverage closes nothing.
    expect(screen.getByTestId('receipt-summary')).toHaveTextContent(/Partial coverage/)
  })

  it('sends the knowledge base before the file', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, previewBody))
    render(<ImportResultsDialog open onOpenChange={vi.fn()} />)
    await chooseFile('detections.xml')
    await userEvent.upload(
      screen.getByLabelText(/Qualys KnowledgeBase/),
      new File(['<KNOWLEDGE_BASE_VULN_LIST_OUTPUT/>'], 'kb.xml', { type: 'text/xml' })
    )
    await userEvent.click(screen.getByRole('button', { name: /Preview/ }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    const form = (fetchMock.mock.calls[0][1] as RequestInit).body as FormData
    expect([...form.keys()]).toEqual(['knowledge_base', 'file'])
  })

  it('shows a refusal with its line and keeps Import disabled', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(400, {
        code: 'BAD_REQUEST',
        message:
          'nessus at line 3: a document type declaration with an internal subset or entities is not allowed',
        details: {
          name: 'evil.nessus',
          stats: { records: 0, assets: 0, findings: 0, components: 0, statements: 0, skipped: 0 },
          error: { kind: 'unsafe', message: 'refused', line: 3 },
        },
      })
    )
    render(<ImportResultsDialog open onOpenChange={vi.fn()} />)
    await chooseFile('evil.nessus')
    await userEvent.click(screen.getByRole('button', { name: /Preview/ }))
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/line 3/))
    expect(screen.getByRole('button', { name: /^Import$/ })).toBeDisabled()
  })

  it('explains a body that is too large', async () => {
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 413,
      json: async () => {
        throw new Error('x')
      },
    })
    render(<ImportResultsDialog open onOpenChange={vi.fn()} />)
    await chooseFile()
    await userEvent.click(screen.getByRole('button', { name: /Preview/ }))
    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent('The file is too large')
    )
  })

  it('says when a stored upload could not be imported', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, previewBody))
    const onImported = vi.fn()
    render(<ImportResultsDialog open onOpenChange={vi.fn()} onImported={onImported} />)
    await chooseFile()
    await userEvent.click(screen.getByRole('button', { name: /Preview/ }))
    await waitFor(() => expect(screen.getByRole('button', { name: /^Import$/ })).toBeEnabled())
    fetchMock.mockResolvedValueOnce(
      jsonResponse(202, {
        ...previewBody,
        dry_run: false,
        receipt_id: 'r2',
        status: 'queued',
        files: [],
      })
    )
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, {
        receipt_id: 'r2',
        status: 'failed',
        error_code: 'apply_failed',
        files: [],
      })
    )
    await userEvent.click(screen.getByRole('button', { name: /^Import$/ }))
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/apply_failed/))
    expect(onImported).not.toHaveBeenCalled()
  })

  it('previews a recon directory: candidates, files skipped on purpose and unmapped files, nothing hidden', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, {
        session_id: 's',
        dry_run: true,
        files: [
          {
            name: 'recon.zip',
            format: 'reconftw',
            layout: 'v4',
            stats: {
              records: 9,
              assets: 7,
              findings: 1,
              components: 0,
              statements: 0,
              skipped: 0,
              endpoints: 4,
            },
            candidates: 3,
            skipped_by_policy: [{ path: 'osint/emails.txt', reason: 'people data' }],
            skipped_by_policy_total: 2,
            unmapped: ['new_tool/out.md'],
            unmapped_total: 1,
          },
        ],
      })
    )
    const user = userEvent.setup()
    render(<ImportResultsDialog open onOpenChange={vi.fn()} />)
    await user.click(screen.getByLabelText('Recon results (reconFTW directory)'))
    expect(screen.getByTestId('recon-hint')).toBeInTheDocument()
    expect(screen.queryByLabelText(/Qualys KnowledgeBase/)).toBeNull()
    const input = screen.getByLabelText('File') as HTMLInputElement
    expect(input.accept).toContain('.zip')
    await userEvent.upload(input, new File(['PK'], 'recon.zip', { type: 'application/zip' }))
    await user.click(screen.getByRole('button', { name: /Preview/ }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    // The server detects the layout: no format is forced.
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/findings/imports?dry_run=true')
    const recon = await screen.findByTestId('recon-summary')
    expect(recon).toHaveTextContent('Hosts outside your scope')
    expect(screen.getByTestId('recon-candidates')).toHaveTextContent(
      /3 hosts are outside your scope/
    )
    expect(recon).toHaveTextContent('2 files skipped on purpose')
    expect(screen.getByText('1 files not recognized')).toBeInTheDocument()
    await user.click(screen.getByText('2 files skipped on purpose'))
    expect(screen.getByText('osint/emails.txt')).toBeInTheDocument()
  })
})
