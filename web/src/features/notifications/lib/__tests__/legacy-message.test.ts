import { describe, expect, it } from 'vitest'
import { translate } from '@/lib/i18n'
import { vi } from '@/lib/i18n/dictionaries'
import { serverText, type Translate } from '@/lib/server-text'
import { legacyCoverageMessage } from '../legacy-message'

const tVi: Translate = (key, fallback, vars) => translate(vi, key, fallback, vars, 'vi')

// Stored text exactly as the server wrote it before message codes.
const paused = {
  title: 'Coverage paused: capture.screenshot',
  body:
    'capture.screenshot is paused on 4 assets: screenshots are off for this organization. ' +
    'Turn screenshots on in the attack surface monitoring settings if your organization wants them; the pairs become due at once.',
}

describe('legacyCoverageMessage', () => {
  it('reads back a stored readiness notice', () => {
    const m = legacyCoverageMessage('coverage_gap', paused.title, paused.body)
    expect(m).toEqual({
      code: 'coverage.readiness',
      params: {
        capability: 'capture.screenshot',
        count: 4,
        readiness: { code: 'coverage.readiness.feature_off' },
        action: { code: 'coverage.action.feature_off' },
      },
    })
    const body = serverText(tVi, 'vi', m, paused.body, 'body')
    expect(body).not.toContain('capture.screenshot')
    expect(body).toContain('4 tài sản')
  })

  it('reads back a digest line by line', () => {
    const body = [
      "- 7 assets did not answer probe.http from your sensors; they are checked again on a widening schedule. Check that a sensor in the targets' network can reach them, or retire assets that are gone.",
      '- lookup.asn failed 3 or more times in a row on 2 assets. Open the assets to see which ones and why.',
    ].join('\n')
    const m = legacyCoverageMessage('coverage_gap', 'Coverage: 2 changes', body)
    expect(m?.code).toBe('coverage.digest')
    expect((m?.params?.lines as unknown[]).length).toBe(2)
  })

  it('leaves anything else to the stored text', () => {
    expect(legacyCoverageMessage('finding_new', paused.title, paused.body)).toBeUndefined()
    // An unknown reason phrase.
    expect(
      legacyCoverageMessage(
        'coverage_gap',
        paused.title,
        paused.body.replace('screenshots are off', 'x')
      )
    ).toBeUndefined()
    // The title names another capability.
    expect(
      legacyCoverageMessage('coverage_gap', 'Coverage paused: probe.http', paused.body)
    ).toBeUndefined()
    // A digest whose count does not match its lines, or with a line that does not parse.
    expect(
      legacyCoverageMessage('coverage_gap', 'Coverage: 3 changes', `- ${paused.body}`)
    ).toBeUndefined()
    expect(
      legacyCoverageMessage('coverage_gap', 'Coverage: 1 changes', '- something else')
    ).toBeUndefined()
    // A capability that is not a key.
    expect(
      legacyCoverageMessage(
        'coverage_gap',
        'Coverage paused: <b>x</b>',
        paused.body.replace('capture.screenshot', '<b>x</b>')
      )
    ).toBeUndefined()
  })
})
