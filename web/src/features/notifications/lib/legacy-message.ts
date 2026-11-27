/**
 * Best-effort message codes for coverage notices stored before the server
 * sent `message_code` (their stored English text named raw capability keys).
 *
 * Only exact, fixed sentence shapes are read back: the capability must be a
 * capability key, counts digits, and the reason and action sentences must be
 * one of the server's fixed phrases (PHRASES). Anything else returns undefined
 * and the row shows its stored text, so nothing is ever guessed or lost.
 */

import type { ServerMessage } from '@/lib/server-text'

const CAP = '([a-z][a-z0-9_]*\\.[a-z0-9_]+)'
const N = '(\\d{1,9})'

/**
 * The fixed English phrases the server wrote into coverage notices before
 * message codes, by code. Stored rows never change, so this list is frozen:
 * new phrases arrive with a code and never need reading back.
 */
const PHRASES: Record<string, string> = {
  'The deferred origins run when the daily request budget allows; nothing to do.':
    'coverage.action.budget',
  'Ask the instance administrator to import the platform wordlist pack; coverage resumes on its own.':
    'coverage.action.content_missing',
  'Add the API key the tool needs.': 'coverage.action.credentials_missing',
  'Turn screenshots on in the attack surface monitoring settings if your organization wants them; the pairs become due at once.':
    'coverage.action.feature_off',
  'Install a sensor, or assign one to the scan zone.': 'coverage.action.no_eligible_sensor',
  'Add your domains and ranges to scope.': 'coverage.action.no_scope',
  'Open a waiting run\'s "Why waiting?" or check the sensors\' grants and policies; coverage tries again on its own.':
    'coverage.action.not_claimed',
  'Open the assets to see which ones and why.': 'coverage.action.open_assets',
  'Turn the tool on in Settings > Scanning > Tools, or check scan approval and windows.':
    'coverage.action.policy_disabled',
  'It resumes at 00:00 UTC; add your own sensor to scan more.': 'coverage.action.quota_exhausted',
  'Start the sensor, or wait until it reconnects.': 'coverage.action.sensor_offline',
  "Update the sensor to the tool's minimum version.": 'coverage.action.sensor_outdated',
  'Turn path discovery on in the scope settings to run it.': 'coverage.action.switched_off',
  'Add the tool to a sensor (Settings > Scanning > Tools shows how).':
    'coverage.action.tool_missing',
  "Allow the tool in the sensor's grant or local policy.": 'coverage.action.tool_not_allowed',
  "Check that a sensor in the targets' network can reach them, or retire assets that are gone.":
    'coverage.action.unreachable',
  "today's request budget is spent; the rest is deferred": 'coverage.readiness.budget',
  'the platform has no wordlist pack for its tool yet': 'coverage.readiness.content_missing',
  'an API key it needs is not configured': 'coverage.readiness.credentials_missing',
  'screenshots are off for this organization': 'coverage.readiness.feature_off',
  'no sensor can take the work': 'coverage.readiness.no_eligible_sensor',
  'the organization has no scope entry': 'coverage.readiness.no_scope',
  'no sensor took its last runs': 'coverage.readiness.not_claimed',
  'an organization policy holds it': 'coverage.readiness.policy_disabled',
  "today's shared scanning quota is used up": 'coverage.readiness.quota_exhausted',
  'the sensors with its tool are offline': 'coverage.readiness.sensor_offline',
  'the sensors with its tool are too old': 'coverage.readiness.sensor_outdated',
  'the organization turned it off': 'coverage.readiness.switched_off',
  'no sensor has the tool it needs': 'coverage.readiness.tool_missing',
  "the sensors' policy does not allow its tool": 'coverage.readiness.tool_not_allowed',
}

/** The code of a fixed English phrase under a code prefix. */
function phraseCode(prefix: string, text: string): string | undefined {
  const code = Object.hasOwn(PHRASES, text) ? PHRASES[text] : undefined
  return code?.startsWith(`${prefix}.`) ? code : undefined
}

type LineParser = (line: string) => ServerMessage | undefined

const lineParsers: LineParser[] = [
  (line) => {
    const m = new RegExp(`^${CAP} is paused on ${N} assets?: (.+?)\\. (.+)$`).exec(line)
    if (!m) return undefined
    const readiness = phraseCode('coverage.readiness', m[3])
    const action = phraseCode('coverage.action', m[4])
    if (!readiness || !action) return undefined
    return {
      code: 'coverage.readiness',
      params: {
        capability: m[1],
        count: Number(m[2]),
        readiness: { code: readiness },
        action: { code: action },
      },
    }
  },
  (line) => {
    const m = new RegExp(
      `^In the last 24 hours ${CAP} ran on ${N} assets? that should have produced output and produced none\\. The tool may be broken or blocked\\. (.+)$`
    ).exec(line)
    const action = m && phraseCode('coverage.action', m[3])
    if (!m || !action) return undefined
    return {
      code: 'coverage.output_drop',
      params: { capability: m[1], count: Number(m[2]), action: { code: action } },
    }
  },
  (line) => {
    const m = new RegExp(
      `^${CAP} failed ${N} or more times in a row on ${N} assets?\\. (.+)$`
    ).exec(line)
    const action = m && phraseCode('coverage.action', m[4])
    if (!m || !action) return undefined
    return {
      code: 'coverage.failing',
      params: {
        capability: m[1],
        streak: Number(m[2]),
        count: Number(m[3]),
        action: { code: action },
      },
    }
  },
  (line) => {
    const m = new RegExp(
      `^${N} assets? did not answer ${CAP} from your sensors; they are checked again on a widening schedule\\. (.+)$`
    ).exec(line)
    const action = m && phraseCode('coverage.action', m[3])
    if (!m || !action) return undefined
    return {
      code: 'coverage.unreachable',
      params: { capability: m[2], count: Number(m[1]), action: { code: action } },
    }
  },
  (line) => {
    const m = new RegExp(
      `^${N} assets? that need ${CAP} have not had it for more than twice its cadence \\(or never\\)\\. (.+)$`
    ).exec(line)
    const action = m && phraseCode('coverage.action', m[3])
    if (!m || !action) return undefined
    return {
      code: 'coverage.gap',
      params: { capability: m[2], count: Number(m[1]), action: { code: action } },
    }
  },
]

function parseLine(line: string): ServerMessage | undefined {
  for (const parse of lineParsers) {
    const m = parse(line)
    if (m) return m
  }
  return undefined
}

/** The message of a stored coverage notice, or undefined when its text is not one of the fixed shapes. */
export function legacyCoverageMessage(
  notificationType: string,
  title: string,
  body: string | undefined
): ServerMessage | undefined {
  if (notificationType !== 'coverage_gap' || !body || body.length > 20_000) return undefined
  const digest = /^Coverage: (\d{1,6}) changes$/.exec(title)
  if (digest) {
    const lines = body.split('\n')
    if (lines.length !== Number(digest[1])) return undefined
    const items: ServerMessage[] = []
    for (const line of lines) {
      if (!line.startsWith('- ')) return undefined
      const m = parseLine(line.slice(2))
      if (!m) return undefined
      items.push(m)
    }
    return { code: 'coverage.digest', params: { count: items.length, lines: items } }
  }
  const m = parseLine(body)
  // The title names the same capability as the body, or the row is not read back.
  if (!m) return undefined
  const cap = String(m.params?.capability)
  return title.endsWith(` ${cap}`) || title.includes(`${cap} `) ? m : undefined
}
