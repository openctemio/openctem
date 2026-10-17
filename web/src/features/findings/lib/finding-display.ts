/**
 * How a finding reads in the drawer, without changing what is stored:
 *
 * - displayTitle: drops a leading "pkg: " the scanner repeats from the
 *   package ("django: Django SQL injection" → "Django SQL injection"),
 *   names a secret by its kind and file ("Generic API Key in
 *   app/settings.py"), and uses a SAST message instead of a rule slug.
 * - userTags: the tags people set, without the scanner artefacts importers
 *   add (the tool name, the finding type, the scanned file).
 *
 * The stored title and tags stay the scanner's: search, dedup and tickets use
 * them, and the full page shows them.
 */

import { defaultT, type TFn } from '@/features/assets/lib/default-t'
import type { FindingDetail } from '../types'

type TitleInput = Pick<
  FindingDetail,
  'title' | 'source' | 'component' | 'filePath' | 'ruleId' | 'ruleName' | 'message'
>

const PKG_PREFIX = /^([A-Za-z0-9@/._-]{1,80}):\s+([\s\S]+)$/
const DISTRO_PREFIX =
  /^(python|python3|golang|go|node|nodejs|ruby|rubygem|php|perl|rust|java|lib)-/i

function sameName(a: string, b: string): boolean {
  const norm = (s: string) => s.toLowerCase().replace(DISTRO_PREFIX, '').replace(/[-_.]/g, '')
  return norm(a) === norm(b)
}

/**
 * Moves a leading "<package>: " that names the finding's package out of the
 * way: dropped when the rest still names the package ("django: Django SQL
 * injection"), else moved to the end ("PyYAML: arbitrary command execution"
 * → "Arbitrary command execution in PyYAML").
 */
function stripPackagePrefix(title: string, pkg: string | undefined, t: TFn): string {
  let out = title
  let removed = ''
  for (let i = 0; i < 3; i++) {
    const m = PKG_PREFIX.exec(out)
    if (!m) break
    const prefix = m[1]
    const rest = m[2].trim()
    const firstWord = rest.split(/[\s:]/)[0] ?? ''
    if (!(pkg && sameName(prefix, pkg)) && !sameName(prefix, firstWord)) break
    removed = removed || prefix
    out = rest
  }
  if (!removed) return title
  const name = pkg || removed
  if (out.toLowerCase().includes(name.toLowerCase())) return out
  const issue = /^[a-z][a-z]*\s/.test(out) ? out.charAt(0).toUpperCase() + out.slice(1) : out
  return t('findings.display.inPackage', '{issue} in {package}', { issue, package: name })
}

const SECRET_TITLE = /^(?:detected|found)\s+(?:an?\s+)?(.+?)(?:,|\.|$)/i

export function displayTitle(f: TitleInput, t: TFn = defaultT): string {
  const raw = (f.title ?? '').trim()
  if (!raw) return raw
  if (f.source === 'secret' && f.filePath) {
    const m = SECRET_TITLE.exec(raw)
    if (m && m[1].length <= 60) {
      return t('findings.display.secretIn', '{secret} in {file}', {
        secret: m[1].trim(),
        file: f.filePath,
      })
    }
  }
  if (f.source === 'sast' && f.message && f.ruleName && raw === f.ruleName) {
    const first = f.message
      .split(/(?<=[.!?])\s/)[0]
      ?.trim()
      .replace(/\.$/, '')
    if (first && first.length <= 140) return first
  }
  return stripPackagePrefix(raw, f.component?.name, t)
}

const ARTEFACT_TAGS = new Set([
  'secret',
  'misconfiguration',
  'vulnerability',
  'sast',
  'sca',
  'iac',
  'dast',
])

export function userTags(
  f: Pick<FindingDetail, 'tags' | 'toolName' | 'filePath' | 'source' | 'findingType'>
): string[] {
  const drop = new Set(
    [f.toolName, f.filePath, f.source, f.findingType]
      .filter((x): x is string => !!x)
      .map((x) => x.toLowerCase())
  )
  return (f.tags ?? []).filter((tag) => {
    const k = tag.toLowerCase()
    return !drop.has(k) && !ARTEFACT_TAGS.has(k)
  })
}
