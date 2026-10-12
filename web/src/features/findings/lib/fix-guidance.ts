/**
 * "How do I fix it?" — the one action the finding's Fix card leads with, per
 * finding type, built only from data the finding has:
 *
 *   dependency (SCA / container)  upgrade <package> <from> → <to>, with the
 *                                 command for its ecosystem
 *   secret                        revoke and rotate the credential
 *   misconfiguration              set <resource> to the expected value
 *   code (SAST and the rest)      the scanner's fix / recommendation
 *
 * Returns null when there is nothing concrete to say; the card then hides
 * rather than printing "no recommendation".
 */

import type { FindingDetail } from '../types'

export interface FixCommand {
  /** What the snippet is ("npm", "package.json overrides"). */
  label: string
  code: string
  /** One short line after the snippet ("Then run npm install."). */
  note?: string
}

export type FixGuidance =
  | {
      kind: 'upgrade'
      packageName: string
      from: string
      to: string
      ecosystem: string
      /** direct | transitive | undefined (unknown). */
      dependencyType?: string
      manifestFile?: string
      commands: FixCommand[]
      /** Other release lines with a fix (6.0.6 when the advice is 7.0.5). */
      otherFixedVersions: string[]
    }
  | {
      kind: 'no-fix'
      packageName: string
      from: string
    }
  | {
      kind: 'rotate-secret'
      service?: string
      maskedValue?: string
      inHistoryOnly?: boolean
      steps: string[]
    }
  | {
      kind: 'misconfig'
      resource?: string
      expected?: string
      actual?: string
      policy?: string
    }
  | {
      kind: 'text'
      text: string
      fixCode?: string
    }

/** The upgrade command(s) for a package, by ecosystem. */
export function upgradeCommands(
  ecosystem: string,
  name: string,
  version: string,
  dependencyType?: string
): FixCommand[] {
  const eco = ecosystem.toLowerCase()
  const transitive = dependencyType === 'transitive'
  switch (eco) {
    case 'npm':
      // A transitive package cannot be installed over the parent's range; pin
      // it with an override (npm 8.3+), as the npm documentation advises.
      return transitive
        ? [
            {
              label: 'package.json overrides',
              code: `"overrides": {\n  "${name}": "^${version}"\n}`,
              note: 'Then run npm install. Better still, upgrade the package that pulls it in.',
            },
          ]
        : [{ label: 'npm', code: `npm install ${name}@^${version}` }]
    case 'yarn':
      return [{ label: 'yarn', code: `yarn up ${name}@^${version}` }]
    case 'pnpm':
      return [{ label: 'pnpm', code: `pnpm update ${name}@^${version}` }]
    case 'pypi':
    case 'pip':
    case 'python':
      return [{ label: 'pip', code: `pip install "${name}>=${version}"` }]
    case 'go':
    case 'golang':
      return [{ label: 'go', code: `go get ${name}@v${version.replace(/^v/, '')}` }]
    case 'cargo':
    case 'crates.io':
      return [{ label: 'cargo', code: `cargo update -p ${name} --precise ${version}` }]
    case 'rubygems':
    case 'gem':
      return [{ label: 'Gemfile', code: `gem '${name}', '>= ${version}'` }]
    case 'nuget':
      return [{ label: 'dotnet', code: `dotnet add package ${name} --version ${version}` }]
    case 'composer':
    case 'packagist':
      return [{ label: 'composer', code: `composer require ${name}:^${version}` }]
    case 'maven': {
      const [group, artifact] = name.includes(':') ? name.split(':') : ['', name]
      return [
        {
          label: 'pom.xml',
          code: `<dependency>\n  <groupId>${group}</groupId>\n  <artifactId>${artifact}</artifactId>\n  <version>${version}</version>\n</dependency>`,
        },
      ]
    }
    default:
      return []
  }
}

function meta(f: Pick<FindingDetail, 'metadata'>, ...keys: string[]): string {
  for (const k of keys) {
    const v = f.metadata?.[k]
    if (typeof v === 'string' && v.trim()) return v.trim()
  }
  return ''
}

/** Scanner boilerplate that says nothing. */
const EMPTY_RECOMMENDATIONS = new Set(['', 'no recommendation provided by scanner.'])

export function fixGuidance(
  f: Pick<
    FindingDetail,
    | 'component'
    | 'advisory'
    | 'secretDetails'
    | 'misconfigDetails'
    | 'findingType'
    | 'source'
    | 'apiRemediation'
    | 'remediation'
    | 'fixCode'
    | 'metadata'
  >
): FixGuidance | null {
  // --- Dependency: upgrade --------------------------------------------------
  const pkg = f.component?.name || meta(f, 'package_name', 'component_name')
  const from = f.component?.version || meta(f, 'installed_version', 'current_version')
  if (pkg && from) {
    const fixed = f.advisory?.fixedVersions ?? []
    const to = f.component?.fixedIn || meta(f, 'fixed_version', 'patched_version')
    const ecosystem = f.component?.ecosystem || meta(f, 'ecosystem', 'package_manager')
    if (to) {
      return {
        kind: 'upgrade',
        packageName: pkg,
        from,
        to,
        ecosystem,
        dependencyType: f.component?.dependencyType,
        manifestFile: f.component?.manifestFile,
        commands: ecosystem ? upgradeCommands(ecosystem, pkg, to, f.component?.dependencyType) : [],
        otherFixedVersions: fixed.filter((v) => v !== to),
      }
    }
    if (f.advisory && fixed.length === 0) {
      return { kind: 'no-fix', packageName: pkg, from }
    }
  }

  // --- Secret: revoke and rotate -------------------------------------------
  const s = f.secretDetails
  if (s || f.findingType === 'secret' || f.source === 'secret') {
    const service = s?.service
    const steps = [
      `Revoke the exposed ${service ? `${service} ` : ''}credential at its provider; deleting the file or commit does not invalidate it.`,
      'Issue a new credential and store it in a secret manager, not in code or configuration.',
      s?.inHistoryOnly
        ? 'Purge it from the repository history (git filter-repo or BFG), then force-push.'
        : 'Remove it from the code and purge it from the repository history.',
      'Review the provider’s access logs for use since it was exposed.',
    ]
    return {
      kind: 'rotate-secret',
      service,
      maskedValue: s?.maskedValue,
      inHistoryOnly: s?.inHistoryOnly,
      steps,
    }
  }

  // --- Misconfiguration: set the expected value ----------------------------
  const m = f.misconfigDetails
  if (m && (m.expected || m.actual)) {
    return {
      kind: 'misconfig',
      resource: [m.resourceType, m.resourceName].filter(Boolean).join(' ') || m.resourcePath,
      expected: m.expected,
      actual: m.actual,
      policy: m.policyName || m.policyId,
    }
  }

  // --- Everything else: the scanner's / analyst's advice --------------------
  const text =
    f.apiRemediation?.preferred_fix ||
    f.apiRemediation?.recommendation ||
    f.remediation?.description ||
    ''
  const fixCode = f.apiRemediation?.fix_code || f.fixCode
  if (!EMPTY_RECOMMENDATIONS.has(text.trim().toLowerCase()) || fixCode) {
    return { kind: 'text', text: text.trim(), fixCode: fixCode || undefined }
  }
  return null
}
