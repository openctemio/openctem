import { describe, it, expect } from 'vitest'
import {
  complianceCheckOf,
  complianceDescriptionText,
  complianceOutcome,
  parseComplianceReferences,
  parseComplianceSubChecks,
  splitComplianceDescription,
} from '../compliance-check'
import type { FindingDetail } from '../../types'

// The actual value of a check that needs several conditions (example data).
const ACTUAL = `All of the following must pass to satisfy this requirement:

-------------------------
PASSED - pam_faillock.so preauth in system-auth
The file "/etc/authselect/custom/example/system-auth" contains "^\\s*auth\\s+required\\s+pam_faillock\\.so\\s+preauth"

auth required pam_faillock.so preauth silent

-------------------------
FAILED - pam_faillock.so authfail in password-auth
The file "/etc/authselect/custom/example/password-auth" does not contain "^\\s*auth\\s+required\\s+pam_faillock\\.so\\s+authfail"
-------------------------
WARNING - pam_faillock.so account in system-auth
expect: ^\\s*account\\s+required\\s+pam_faillock\\.so`

describe('parseComplianceSubChecks', () => {
  it('parses each sub-check, failed first, with its file and expression', () => {
    const { preamble, subChecks } = parseComplianceSubChecks(ACTUAL)
    expect(preamble).toBe('All of the following must pass to satisfy this requirement:')
    expect(subChecks.map((s) => s.outcome)).toEqual(['FAILED', 'WARNING', 'PASSED'])
    const [failed, warning, passed] = subChecks
    expect(failed.name).toBe('pam_faillock.so authfail in password-auth')
    expect(failed.file).toBe('/etc/authselect/custom/example/password-auth')
    expect(failed.expect).toBe('^\\s*auth\\s+required\\s+pam_faillock\\.so\\s+authfail')
    expect(warning.expect).toBe('^\\s*account\\s+required\\s+pam_faillock\\.so')
    expect(passed.file).toBe('/etc/authselect/custom/example/system-auth')
    expect(passed.detail).toContain('auth required pam_faillock.so preauth silent')
  })

  it('reads the "----- FAILED - name" one-line form', () => {
    const { subChecks } = parseComplianceSubChecks(
      '----- PASSED - a\nok\n----- FAILED - b\nThe file "/etc/example.conf" does not contain "x"'
    )
    expect(subChecks.map((s) => [s.outcome, s.name])).toEqual([
      ['FAILED', 'b'],
      ['PASSED', 'a'],
    ])
    expect(subChecks[0].file).toBe('/etc/example.conf')
  })

  it('returns no sub-checks for a value without them', () => {
    expect(parseComplianceSubChecks('The command returned :\n\npermitrootlogin yes')).toEqual({
      preamble: '',
      subChecks: [],
    })
  })
})

describe('parseComplianceReferences', () => {
  it('groups by framework in source order, without duplicates', () => {
    const g = parseComplianceReferences(
      '800-53|AC-7,CSCv8|6.2,800-53|AC-7,800-53|AC-6(2),NESA|T1.2.1,NESA|T5.4.4'
    )
    expect(g.map((x) => [x.framework, x.label, x.ids])).toEqual([
      ['800-53', 'NIST SP 800-53', ['AC-7', 'AC-6(2)']],
      ['CSCv8', 'CIS Controls v8', ['6.2']],
      ['NESA', 'NESA', ['T1.2.1', 'T5.4.4']],
    ])
  })
  it('is empty for nothing', () => {
    expect(parseComplianceReferences(undefined)).toEqual([])
  })
})

const DESCRIPTION = `"5.3.2.2 Ensure pam_faillock module is enabled" : [FAILED]

The pam_faillock.so module maintains a list of failed authentication attempts.

Rationale:
Locking out user IDs after unsuccessful attempts slows password guessing.

Reference: 800-53|AC-7,NESA|T1.2.1

Policy Value:
expect: pam_faillock

Actual Value:
${ACTUAL}`

describe('compliance description', () => {
  it('splits the headline and labelled sections', () => {
    const p = splitComplianceDescription(DESCRIPTION)
    expect(p.headline).toEqual({
      check: '5.3.2.2 Ensure pam_faillock module is enabled',
      outcome: 'FAILED',
    })
    expect(p.body).toBe(
      'The pam_faillock.so module maintains a list of failed authentication attempts.'
    )
    expect(p.sections.map((s) => s.name)).toEqual([
      'Rationale',
      'Reference',
      'Policy Value',
      'Actual Value',
    ])
  })

  it('drops the sections the panel shows, keeps the rest', () => {
    const f = finding({ description: DESCRIPTION })
    const check = complianceCheckOf(f)!
    const text = complianceDescriptionText(DESCRIPTION, check)
    expect(text).toContain('The pam_faillock.so module')
    expect(text).toContain('Rationale:\nLocking out')
    expect(text).not.toContain('Policy Value')
    expect(text).not.toContain('Actual Value')
    expect(text).not.toContain('Reference:')
    expect(text).not.toContain('[FAILED]')
  })

  it('leaves a description without sections as it is', () => {
    const check = complianceCheckOf(finding({ description: 'Plain text.' }))!
    expect(complianceDescriptionText('Plain text.', check)).toBe('Plain text.')
  })
})

function finding(over: Partial<FindingDetail> = {}): FindingDetail {
  return {
    title: '5.3.2.2 Ensure pam_faillock module is enabled',
    findingType: 'compliance',
    ...over,
  } as FindingDetail
}

describe('complianceCheckOf', () => {
  it('reads the source fields and the scanner output', () => {
    const check = complianceCheckOf(
      finding({
        complianceDetails: {
          framework: 'cis',
          frameworkVersion: '1.0.0',
          controlId: 'c0ffee00',
          controlName: '5.3.2.2 Ensure pam_faillock module is enabled',
          result: 'fail',
        },
        sourceData: {
          scores: [],
          vulnerabilityIds: [],
          sourceExtra: [
            ['compliance-audit-file', 'CIS_Example_Linux_L1_v1.0.0.audit'],
            ['compliance-benchmark-name', 'CIS Example Linux'],
            ['compliance-benchmark-profile', 'Level 1 - Server'],
            ['compliance-policy-value', 'expect: pam_faillock'],
            ['compliance-reference', '800-53|AC-7,NESA|T1.2.1'],
            ['compliance-result', 'FAILED'],
            ['plugin_type', 'local'],
          ],
        } as unknown as FindingDetail['sourceData'],
        scannerOutput: { text: ACTUAL, truncated: false },
      })
    )!
    expect(check.outcome).toBe('FAILED')
    expect(check.benchmark).toBe('CIS Example Linux')
    expect(check.benchmarkVersion).toBe('1.0.0')
    expect(check.profile).toBe('Level 1 - Server')
    expect(check.control).toBe('5.3.2.2')
    expect(check.auditFile).toBe('CIS_Example_Linux_L1_v1.0.0.audit')
    expect(check.policyValue).toBe('expect: pam_faillock')
    expect(check.subChecks).toHaveLength(3)
    expect(check.references.map((r) => r.framework)).toEqual(['800-53', 'NESA'])
    expect(check.shownExtraKeys).not.toContain('plugin_type')
    expect(check.shownExtraKeys).toContain('compliance-reference')
  })

  it('falls back to the description sections', () => {
    const check = complianceCheckOf(finding({ description: DESCRIPTION }))!
    expect(check.outcome).toBe('FAILED')
    expect(check.policyValue).toBe('expect: pam_faillock')
    expect(check.subChecks[0].outcome).toBe('FAILED')
    expect(check.references).toHaveLength(2)
  })

  it('prefers the importer structured sub-checks and mappings', () => {
    const subchecks = JSON.stringify([
      {
        result: 'pass',
        title: 'Example file has the expected owner',
        detail: 'File: /etc/example/example.conf; Regex: ^owner=root; Matched lines:; owner=root',
      },
      {
        result: 'fail',
        title: 'Example setting is enabled',
        detail: 'File: /etc/example/example.conf; Regex: ^enabled=yes; No matching lines',
      },
      { result: 'review', title: 'Example item needs review', detail: 'Manual review needed' },
    ])
    const check = complianceCheckOf(
      finding({
        sourceData: {
          scores: [],
          vulnerabilityIds: [],
          sourceExtra: [
            ['compliance-subchecks', subchecks],
            [
              'compliance-mappings',
              'nist_800_53||CM-6\ncis|controls v8|4.1\npci_dss|3.2.1|2.2\nnist_800_53||CM-7',
            ],
            ['compliance-reference', '800-53|CM-6'],
            ['compliance-error', 'The file /var/log/example/audit.log could not be read'],
          ],
        } as unknown as FindingDetail['sourceData'],
      })
    )!
    expect(check.subChecks.map((s) => [s.outcome, s.name])).toEqual([
      ['FAILED', 'Example setting is enabled'],
      ['WARNING', 'Example item needs review'],
      ['PASSED', 'Example file has the expected owner'],
    ])
    expect(check.subChecks[0]).toMatchObject({
      file: '/etc/example/example.conf',
      expect: '^enabled=yes',
    })
    expect(check.references.map((r) => [r.label, r.ids])).toEqual([
      ['NIST SP 800-53', ['CM-6', 'CM-7']],
      ['CIS Controls v8', ['4.1']],
      ['PCI DSS 3.2.1', ['2.2']],
    ])
    expect(check.error).toBe('The file /var/log/example/audit.log could not be read')
    expect(check.shownExtraKeys).toEqual(
      expect.arrayContaining(['compliance-subchecks', 'compliance-mappings', 'compliance-error'])
    )
  })

  it('ignores a malformed structured value and parses the text', () => {
    const check = complianceCheckOf(
      finding({
        sourceData: {
          scores: [],
          vulnerabilityIds: [],
          sourceExtra: [['compliance-subchecks', '{not json']],
        } as unknown as FindingDetail['sourceData'],
        scannerOutput: { text: ACTUAL, truncated: false },
      })
    )!
    expect(check.subChecks[0].name).toBe('pam_faillock.so authfail in password-auth')
  })

  it('is undefined for a vulnerability', () => {
    expect(complianceCheckOf(finding({ findingType: 'vulnerability' }))).toBeUndefined()
  })

  it('maps the CTIS result when the source value is missing', () => {
    expect(complianceOutcome(undefined, 'pass')).toBe('PASSED')
    expect(complianceOutcome('failed')).toBe('FAILED')
    expect(complianceOutcome(undefined, 'manual')).toBe('WARNING')
    expect(complianceOutcome(undefined, undefined)).toBeUndefined()
  })
})
