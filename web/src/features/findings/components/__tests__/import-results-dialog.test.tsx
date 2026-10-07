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
  })

  it('sends the minimum severity a caller sets (the scanners page skips info)', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, previewBody))
    render(<ImportResultsDialog open onOpenChange={vi.fn()} minSeverity="low" />)
    await chooseFile()
    await userEvent.click(screen.getByRole('button', { name: /Preview/ }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/findings/import?dry_run=true&min_severity=low')
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
    expect(url).toBe('/api/v1/findings/import?dry_run=true')
    expect((init as RequestInit).method).toBe('POST')
    expect(screen.getByText('Nessus (.nessus)')).toBeInTheDocument()
    expect(screen.getByText('high: 2')).toBeInTheDocument()
    expect(screen.getByText('line 12: host skipped')).toBeInTheDocument()
    expect(screen.getByText(/1 source fields not recognized/)).toBeInTheDocument()
    expect(onImported).not.toHaveBeenCalled()
    // A file name from the upload is text, never markup.
    expect(screen.getByText('<img src=x onerror=alert(1)>.nessus')).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull()

    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, {
        ...previewBody,
        dry_run: false,
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
    expect(fetchMock.mock.calls[1][0]).toBe('/api/v1/findings/import')
    expect(screen.getByText(/2 findings created/)).toBeInTheDocument()
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
})
