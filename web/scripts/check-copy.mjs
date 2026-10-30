#!/usr/bin/env node
/**
 * Copy linter for the web console's English dictionaries (research/237 R12,
 * R18, R19; research/236 F5). It gates the strings a pull request ADDS or
 * CHANGES (compared with the merge base), the same model as the separator and
 * palette gates, so existing debt is fixed in clean-up PRs, not by blocking
 * every change. `--all` reports every string (the clean-up list).
 *
 *   node scripts/check-copy.mjs [base-ref]    gate changed strings (default origin/develop)
 *   node scripts/check-copy.mjs --all         list every finding, exit 0
 *   node scripts/check-copy.mjs --file <json> check one dictionary file (website en.json)
 *
 * Rules (English values):
 *   banned     marketing words: seamless, supercharge, effortless, empower,
 *              streamline, leverage, robust, powerful, delve, cutting-edge,
 *              next-gen, game-changer, revolutionize, elevate (as marketing)
 *   success    "successfully", "Success!"
 *   bang       a value ending in "!"
 *   notjust    "not just", "isn't just", "not only"
 *   emdash     an em dash inside a string (the lone "—" placeholder is fine)
 *   middot     a " · " separator
 *   titlecase  a short label (one phrase, up to 7 words) with three or more
 *              capitalised words in a row that are not a known proper noun
 *              (sentence case, research/236 C2)
 */
import { execFileSync } from 'node:child_process'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

const DICT_DIR = 'src/lib/i18n/dictionaries/en'

// Keys whose words are real security terms, not marketing.
const KEY_ALLOW = [/^admin\.users\.action\.unlock/, /^admin\.elevation\./]

const BANNED =
  /\b(seamless(ly)?|supercharge[sd]?|effortless(ly)?|empower(s|ed|ing)?|streamline[sd]?|leverag(e|es|ed|ing)|robust|powerful|delve[sd]?|cutting-edge|next-gen|game-changer|revolutioni[sz]e[sd]?)\b/i
const SUCCESS = /\bsuccessfully\b|\bsuccess!/i
const NOT_JUST = /\bnot just\b|\bisn't just\b|\bnot only\b/i

// Words that are capitalised by nature: products we integrate, standards,
// acronyms are caught by the all-caps test below.
const PROPER = new Set(
  `CISA Tenable SC Qualys Defender Microsoft Entra Azure Google GitHub GitLab Bitbucket Jira Slack Teams
  Telegram Discord PagerDuty Opsgenie Splunk Elastic Sentinel Okta Burp OpenVAS Nmap Nuclei Trivy Semgrep
  Opengrep Kubernetes Docker Linux Windows AWS GCP OpenCTEM CTEM KEV EPSS CVSS CVE CWE OWASP NIST ISO SOC MITRE
  ATT&CK SARIF CTIS SCIM SAML OIDC OAuth TOTP WebAuthn Vietnamese English Monday Tuesday Wednesday Thursday
  Friday Saturday Sunday January February March April May June July August September October November December
  Cmd Ctrl Shift Enter Esc Tab I II III P0 P1 P2 P3`.split(/\s+/)
)
// Names that are Title Case by nature: catalog and standard names, and the
// console's own navigation paths ("Settings, Roles").
const PROPER_PHRASES =
  /Known Exploited Vulnerabilit|Cloudflare Turnstile|Access Control|Outdated Components|Authentication Failures|Integrity Failures|Monitoring Failures|Request Forgery|Cryptographic Failures|Security Misconfiguration|Insecure Design|^Settings, /
const SMALL = new Set(
  'a an and as at but by for from in into nor of on or per the to vs via with'.split(' ')
)

function stripPlaceholders(v) {
  return v.replace(/\{[^}]*\}/g, ' ').replace(/<[^>]*>/g, ' ')
}

function titleCaseRun(v) {
  // Labels, titles and buttons only: short, one phrase. Prose names UI
  // controls and products ("the Reveal secrets permission"), which is fine.
  if (/^e\.g\.?/i.test(v) || /[.:;?]\s/.test(v) || PROPER_PHRASES.test(v)) return false
  const words = stripPlaceholders(v)
    .split(/[\s/]+/)
    .filter(Boolean)
  if (words.length > 7) return false
  let run = 0
  let best = 0
  for (let i = 0; i < words.length; i++) {
    const w = words[i].replace(/^[("'“]+|[)"'”.,:;!?]+$/g, '')
    if (!w) continue
    const cap = /^[A-Z][a-z]/.test(w) && !PROPER.has(w)
    if (cap && i > 0) {
      run++
      best = Math.max(best, run)
    } else if (SMALL.has(w) && run > 0) {
      // "Mean Time to Remediate": small words do not break a run
    } else {
      run = 0
    }
  }
  // The first word is always capitalised; a run of 2 after it = 3 in a row.
  return best >= 2
}

export function checkValue(key, value) {
  if (typeof value !== 'string' || KEY_ALLOW.some((r) => r.test(key))) return []
  const v = value.trim()
  const out = []
  if (BANNED.test(v)) out.push('banned')
  if (SUCCESS.test(v)) out.push('success')
  if (/!\s*$/.test(v) && !/^!/.test(v)) out.push('bang')
  if (NOT_JUST.test(v)) out.push('notjust')
  if (v.length > 1 && v.includes('—')) out.push('emdash')
  if (/\s·\s/.test(v)) out.push('middot')
  if (titleCaseRun(v)) out.push('titlecase')
  return out
}

function readJSON(text) {
  try {
    return JSON.parse(text)
  } catch {
    return {}
  }
}

function baseDict(ref, file) {
  try {
    return readJSON(
      execFileSync('git', ['show', `${ref}:web/${file}`], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      })
    )
  } catch {
    try {
      return readJSON(
        execFileSync('git', ['show', `${ref}:./${file}`], {
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'ignore'],
        })
      )
    } catch {
      return {}
    }
  }
}

const RULE_HELP = {
  banned: 'a marketing word: say what it does in plain words',
  success: '"successfully": state the fact in past tense ("Key revoked.")',
  bang: 'an exclamation mark: plain statements only',
  notjust: '"not just / not only": say the one thing',
  emdash: 'an em dash: use two sentences, a colon or a comma (the lone placeholder is fine)',
  middot: 'a middle-dot separator: separate elements instead',
  titlecase: 'Title Case: write labels and headings in sentence case',
}

function report(findings) {
  for (const f of findings)
    console.log(`${f.file}  ${f.key}: ${f.rules.join(', ')}\n    ${JSON.stringify(f.value)}`)
  const rules = [...new Set(findings.flatMap((f) => f.rules))]
  if (rules.length) {
    console.log('\nWhy:')
    for (const r of rules) console.log(`  ${r}: ${RULE_HELP[r]}`)
  }
}

function main(argv) {
  if (argv[0] === '--file') {
    const d = readJSON(readFileSync(argv[1], 'utf8'))
    const findings = Object.entries(d).flatMap(([k, v]) => {
      const rules = checkValue(k, v)
      return rules.length ? [{ file: argv[1], key: k, value: v, rules }] : []
    })
    report(findings)
    return findings.length ? 1 : 0
  }
  const all = argv[0] === '--all'
  const base = all ? null : argv[0] || 'origin/develop'
  if (base && /(^|\/)(main|master)$/.test(base)) {
    console.log(`check-copy: base is '${base}' (release merge); skipping.`)
    return 0
  }
  let mergeBase = null
  if (base) {
    try {
      mergeBase = execFileSync('git', ['merge-base', base, 'HEAD'], { encoding: 'utf8' }).trim()
    } catch {
      if (process.env.CI) {
        console.error(`check-copy: base ref '${base}' not found (needs fetch-depth: 0).`)
        return 1
      }
      console.error(`check-copy: base ref '${base}' not found; skipping (not CI).`)
      return 0
    }
  }
  const findings = []
  for (const name of readdirSync(DICT_DIR)
    .filter((f) => f.endsWith('.json'))
    .sort()) {
    const file = join(DICT_DIR, name)
    const now = readJSON(readFileSync(file, 'utf8'))
    const before = mergeBase ? baseDict(mergeBase, file) : {}
    for (const [k, v] of Object.entries(now)) {
      if (mergeBase && before[k] === v) continue
      const rules = checkValue(k, v)
      if (rules.length) findings.push({ file, key: k, value: v, rules })
    }
  }
  report(findings)
  if (all) {
    console.log(`\ncheck-copy: ${findings.length} string(s) to clean up.`)
    return 0
  }
  if (findings.length) {
    console.log(`\ncheck-copy: ${findings.length} added or changed string(s) break the copy rules.`)
    return 1
  }
  console.log('check-copy: no added or changed string breaks the copy rules.')
  return 0
}

if (import.meta.url === `file://${process.argv[1]}`) process.exit(main(process.argv.slice(2)))
