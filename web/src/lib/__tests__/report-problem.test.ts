import { describe, expect, it } from 'vitest'
import {
  browserName,
  bugReportUrl,
  diagnosticsText,
  safeErrorCode,
  safeRequestId,
  stripRoute,
  type Diagnostics,
} from '../report-problem'
import { resolveHelpLinks } from '../help-links'
import { DEFAULT_BUG_URL, DEFAULT_FEEDBACK_URL, DEFAULT_SECURITY_URL } from '@/config/help-links'

describe('stripRoute', () => {
  it.each([
    ['/findings/3f2b8c1e-0d4a-4b7e-9a51-6c1d2e3f4a5b', '/findings/:id'],
    ['/assets/12345/edit', '/assets/:id/edit'],
    ['/vulnerabilities/CVE-2024-12345', '/vulnerabilities/:id'],
    ['/invitations/Zm9vYmFy0123456789abcdef', '/invitations/:id'],
    ['/settings/members?email=alice@corp.example#top', '/settings/members'],
    ['/', '/'],
    ['', '/'],
    ['/findings/%E0%A4%A', '/findings/:id'],
    ['/scans/acme-corp', '/scans/acme-corp'],
  ])('%s -> %s', (input, want) => {
    expect(stripRoute(input)).toBe(want)
  })

  it('never lets an e-mail, host or long token through', () => {
    const out = stripRoute('/x/alice@corp.example/api.corp.example/' + 'a'.repeat(40))
    expect(out).toBe('/x/:id/:id/:id')
  })
})

describe('browserName', () => {
  it('reports only the name and major version', () => {
    const chrome =
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
    expect(browserName(chrome)).toBe('Chrome 131')
    expect(
      browserName('Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0')
    ).toBe('Firefox 133')
    expect(browserName('curl/8.0')).toBe('unknown')
  })
})

describe('safe fields', () => {
  it('drops a code or request id that could carry data', () => {
    expect(safeErrorCode('RATE_LIMITED')).toBe('RATE_LIMITED')
    expect(safeErrorCode('failed for alice@corp.example')).toBe('')
    expect(safeRequestId('req_1a2b3c4d5e')).toBe('req_1a2b3c4d5e')
    expect(safeRequestId('has space')).toBe('')
    expect(safeRequestId(42)).toBe('')
  })
})

const diag: Diagnostics = {
  version: 'v0.16.0',
  channel: 'release',
  console: 'app',
  browser: 'Chrome 131',
  route: '/findings/:id',
  requestId: 'req_1a2b3c4d5e',
  errorCode: 'chunk_load',
}

describe('diagnostics', () => {
  it('lists exactly the safe fields', () => {
    expect(diagnosticsText(diag).split('\n')).toEqual([
      'Version: v0.16.0',
      'Channel: release',
      'Console: app',
      'Browser: Chrome 131',
      'Route: /findings/:id',
      'Request ID: req_1a2b3c4d5e',
      'Error code: chunk_load',
    ])
  })

  it('prefills the bug form with the field ids of .github/ISSUE_TEMPLATE/bug.yml', () => {
    const u = new URL(bugReportUrl(diag))
    expect(`${u.origin}${u.pathname}`).toBe('https://github.com/openctemio/openctem/issues/new')
    expect(Object.fromEntries(u.searchParams)).toEqual({
      template: 'bug.yml',
      version: 'v0.16.0',
      browser: 'Chrome 131',
      route: '/findings/:id',
      diagnostics: diagnosticsText(diag),
    })
  })
})

describe('resolveHelpLinks', () => {
  it('defaults: project issue forms and the project security policy', () => {
    const h = resolveHelpLinks({})
    expect(h).toMatchObject({
      bugUrl: DEFAULT_BUG_URL,
      feedbackUrl: DEFAULT_FEEDBACK_URL,
      securityUrl: DEFAULT_SECURITY_URL,
      hidden: false,
      bugIsDefault: true,
    })
  })

  it('takes https operator links and marks the bug link as not the default', () => {
    const h = resolveHelpLinks({
      help_bug_url: 'https://helpdesk.corp.example/new',
      help_feedback_url: 'https://helpdesk.corp.example/idea',
      help_links_disabled: true,
    })
    expect(h.bugUrl).toBe('https://helpdesk.corp.example/new')
    expect(h.bugIsDefault).toBe(false)
    expect(h.hidden).toBe(true)
  })

  it('refuses non-https links and uses the security contact for the security entry', () => {
    const h = resolveHelpLinks({
      help_bug_url: 'javascript:alert(1)',
      help_feedback_url: 'http://plain.example',
      security_contact: 'secops@corp.example',
    })
    expect(h.bugUrl).toBe(DEFAULT_BUG_URL)
    expect(h.feedbackUrl).toBe(DEFAULT_FEEDBACK_URL)
    expect(h.securityUrl).toBe('mailto:secops@corp.example')
    expect(resolveHelpLinks({ security_policy_url: 'https://corp.example/sec' }).securityUrl).toBe(
      'https://corp.example/sec'
    )
  })
})
