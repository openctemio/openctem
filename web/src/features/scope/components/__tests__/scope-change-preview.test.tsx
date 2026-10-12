import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { consequenceText, previewSummary, ScopeChangePreview } from '../scope-change-preview'

describe('ScopeChangePreview', () => {
  it('marks each line in text, not colour alone, and lists the impact', () => {
    render(
      <ScopeChangePreview
        lines={[
          {
            key: '1',
            mark: 'add',
            pattern: '*.example.com.au',
            summary: 'Domain',
            impact: [{ title: 'Newly in scope', names: ['a.example.com.au'] }],
          },
          { key: '2', mark: 'refused', pattern: '*.com.vn', message: 'A public suffix.' },
        ]}
        consequence={{ approvalsRequired: 1, stepUp: true }}
      />
    )
    expect(screen.getByText('adds:')).toBeInTheDocument()
    expect(screen.getByText('refused:')).toBeInTheDocument()
    expect(screen.getByText('Newly in scope: 1')).toBeInTheDocument()
    expect(screen.getByText('A public suffix.')).toBeInTheDocument()
    expect(screen.getByText('Preview: 1 adds, 1 refused')).toBeInTheDocument()
  })

  it('states the consequence before the click', () => {
    expect(consequenceText({ approvalsRequired: 0 })).toBe('Takes effect now.')
    expect(consequenceText({ isRequest: true })).toMatch(/This is a request/)
    expect(consequenceText({ approvalsRequired: 2, stepUp: true })).toBe(
      'Needs 2 approvals from another approver; nothing changes for scans until then. You will be asked to confirm it is you.'
    )
    expect(previewSummary([])).toBe('Preview: no changes')
  })
})
