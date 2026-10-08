import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'

/**
 * Pipeline vocabulary guard (glossary: api/docs/architecture/scan-naming.md).
 *
 * "Pipeline" is a CI word. The graph of steps a scan runs is a scan workflow,
 * one execution of a scan is a scan run, and an event rule is an automation.
 * This fails on the word anywhere in src/ (copy, identifiers, routes, file
 * names) outside the places where it really means a customer's CI pipeline,
 * the markdown rendering pipeline, or a stored id that keeps its spelling.
 *
 * If you are here because it failed: use the glossary name. Add a path below
 * only for a CI (or other non-scan) meaning, with the reason.
 */

const ROOT = join(__dirname, '..', '..', '..')
const EXT = /\.(ts|tsx|json|css)$/

/** Paths where "pipeline" is a CI pipeline or another non-scan meaning. */
const ALLOWED: { path: RegExp; why: string }[] = [
  { path: /^src\/features\/ci-runners\//, why: 'CI pipelines (RFC-051)' },
  { path: /^src\/app\/\(dashboard\)\/\(discovery\)\/ci-cd\//, why: 'CI pipelines page' },
  { path: /^src\/app\/\(dashboard\)\/settings\/scanning\/ci\//, why: 'CI pipeline settings page' },
  { path: /^src\/lib\/api\/generated\//, why: 'generated from the API spec (CI routes)' },
  { path: /^src\/config\/api-route-permissions\.json$/, why: 'generated route map (CI routes)' },
  { path: /^src\/features\/sensors\//, why: 'runner-mode sensors run inside a CI pipeline' },
  { path: /^src\/features\/shared\/components\/tone-pill\.tsx$/, why: 'a CI pipeline status' },
  {
    path: /^src\/features\/assets\/types\/asset\.types\.ts$/,
    why: 'repositories and their CI pipelines',
  },
  {
    path: /^src\/features\/integrations\/types\/integration\.types\.ts$/,
    why: 'SCM CI pipeline feature',
  },
  {
    path: /^src\/features\/access-control\/api\/use-tenant-permissions\.ts$/,
    why: 'integrations.pipelines (CI) module',
  },
  {
    path: /^src\/config\/__tests__\/settings-route-guards\.test\.ts$/,
    why: 'pipelines_int (CI) module slug',
  },
  {
    path: /^src\/config\/(settings-nav|help-links|legacy-routes|sidebar-data)\.ts$/,
    why: 'CI/CD integration copy',
  },
  { path: /^src\/lib\/i18n\/dictionaries\//, why: 'CI/CD integration copy' },
  { path: /^src\/app\/\(dashboard\)\/settings\/api-keys\//, why: 'example key name "CI pipeline"' },
  {
    path: /^src\/app\/\(dashboard\)\/\(discovery\)\/components\/sbom-export\//,
    why: 'CI/CD pipelines consume SBOMs',
  },
  { path: /^src\/lib\/sanitize-markdown/, why: 'the markdown rendering pipeline' },
  {
    path: /^src\/components\/ui\/markdown-preview-xss\.test\.tsx$/,
    why: 'the markdown rendering pipeline',
  },
  {
    path: /^src\/lib\/api\/(workflow-types\.ts|__tests__\/workflow-unsupported\.test\.ts)$/,
    why: 'stored automation action id trigger_pipeline',
  },
  {
    path: /^src\/config\/section-tabs\.ts$/,
    why: 'command palette keyword for the older name (research/60 N12)',
  },
  {
    path: /^src\/config\/__tests__\/scans-nav\.test\.ts$/,
    why: 'asserts the old /pipelines routes are gone',
  },
  { path: /^src\/config\/__tests__\/pipeline-vocabulary\.test\.ts$/, why: 'this guard' },
  {
    path: /^src\/hooks\/__tests__\/list-params-guard\.test\.ts$/,
    why: 'names the CI pipelines view',
  },
]

function walk(path: string, out: string[]) {
  const st = statSync(path)
  if (st.isDirectory()) {
    for (const name of readdirSync(path)) {
      if (name === 'node_modules' || name.startsWith('.')) continue
      walk(join(path, name), out)
    }
  } else if (EXT.test(path)) {
    out.push(path)
  }
}

const rel = (abs: string) => relative(ROOT, abs).split(sep).join('/')

describe('pipeline vocabulary', () => {
  const files: string[] = []
  walk(join(ROOT, 'src'), files)

  it('uses "pipeline" only for CI pipelines and the other allowed meanings', () => {
    const violations: string[] = []
    for (const abs of files) {
      const file = rel(abs)
      if (ALLOWED.some((a) => a.path.test(file))) continue
      if (/pipeline/i.test(file)) violations.push(`${file}: file name`)
      readFileSync(abs, 'utf8')
        .split('\n')
        .forEach((line, i) => {
          if (/pipeline/i.test(line)) violations.push(`${file}:${i + 1}: ${line.trim()}`)
        })
    }
    expect(violations).toEqual([])
  })

  it('has no allow-list entry that matches nothing', () => {
    const paths = files.map(rel)
    const unused = ALLOWED.filter((a) => !paths.some((p) => a.path.test(p))).map((a) => a.why)
    expect(unused).toEqual([])
  })
})
