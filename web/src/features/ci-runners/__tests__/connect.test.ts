import { describe, expect, it } from 'vitest'
import {
  branchRules,
  privateRangesInConsole,
  configNames,
  isPipelineDefinition,
  looksPrivate,
  normaliseIssuer,
  pipelineDefinition,
  refusalFixes,
  refusedDefinition,
  repoRules,
  verifyCause,
} from '../lib/connect'
import type { CITrustConfig } from '../types'
import { privateAllowText } from '../components/ci-verify-cause'

describe('normaliseIssuer', () => {
  it('writes the address as tokens carry it', () => {
    expect(normaliseIssuer('gitlab.example.com/')).toBe('https://gitlab.example.com')
    expect(normaliseIssuer('  HTTPS://GitLab.Example.com//  ')).toBe('https://gitlab.example.com')
    expect(normaliseIssuer('http://gitlab.example.com')).toBe('https://gitlab.example.com')
    expect(normaliseIssuer('https://example.com/gitlab/')).toBe('https://example.com/gitlab')
    expect(normaliseIssuer('https://gitlab.example.com:8443')).toBe(
      'https://gitlab.example.com:8443'
    )
  })
  it('keeps empty empty and refuses what is not an address', () => {
    expect(normaliseIssuer('')).toBe('')
    expect(normaliseIssuer('ftp://x.example.com')).toBe('')
    expect(normaliseIssuer('https://')).toBe('')
  })
})

describe('looksPrivate', () => {
  it('flags private and local hosts', () => {
    for (const h of [
      'https://10.1.2.3',
      'https://192.168.8.5',
      'https://172.20.0.1',
      'https://git.local',
    ])
      expect(looksPrivate(h)).toBe(true)
    for (const h of ['https://gitlab.com', 'https://172.32.0.1', 'https://8.8.8.8'])
      expect(looksPrivate(h)).toBe(false)
  })
})

describe('repoRules', () => {
  it('admits every project of several groups with one configuration', () => {
    expect(repoRules('group', ['acme', 'beta/team', ' gamma/ '], [])).toEqual({
      owners: ['acme', 'gamma'],
      repositories: ['beta/team/**'],
    })
  })
  it('admits projects directly in a group', () => {
    expect(repoRules('direct', ['acme', 'beta/team'], [])).toEqual({
      owners: [],
      repositories: ['acme/*', 'beta/team/*'],
    })
  })
  it('admits a list of projects', () => {
    expect(repoRules('list', ['ignored'], ['acme/api'])).toEqual({
      owners: [],
      repositories: ['acme/api'],
    })
  })
})

describe('branchRules', () => {
  it('defaults to protected refs and maps the other choices', () => {
    expect(branchRules('protected', 'main')).toEqual({ refs: [], require_protected_ref: true })
    expect(branchRules('default', 'develop')).toEqual({
      refs: ['develop'],
      require_protected_ref: false,
    })
    expect(branchRules('all', 'main')).toEqual({ refs: [], require_protected_ref: false })
  })
})

describe('pipelineDefinition', () => {
  it('builds the GitLab ci_config_ref_uri form', () => {
    expect(
      pipelineDefinition('gitlab', {
        host: 'gitlab.example.com',
        project: 'my-group/ci',
        file: 'scan.yml',
        branch: 'main',
      })
    ).toBe('gitlab.example.com/my-group/ci//scan.yml@refs/heads/main')
    expect(
      pipelineDefinition('gitlab', { host: '', project: 'g/p', file: '.gitlab-ci.yml', branch: '' })
    ).toBe('gitlab.com/g/p//.gitlab-ci.yml@refs/heads/main')
  })
  it('builds the GitHub job_workflow_ref form and keeps a full ref', () => {
    expect(
      pipelineDefinition('github', {
        host: '',
        project: 'acme/security',
        file: '.github/workflows/scan.yml',
        branch: 'refs/tags/v*',
      })
    ).toBe('acme/security/.github/workflows/scan.yml@refs/tags/v*')
  })
  it('needs a project and a file', () => {
    expect(pipelineDefinition('gitlab', { host: 'h', project: '', file: 'x', branch: 'm' })).toBe(
      ''
    )
  })
  it('checks a pasted value', () => {
    expect(isPipelineDefinition('gitlab', 'h/g/p//.gitlab-ci.yml@refs/heads/main')).toBe(true)
    expect(isPipelineDefinition('gitlab', 'h/g/p/.gitlab-ci.yml@refs/heads/main')).toBe(false)
    expect(isPipelineDefinition('github', 'a/b/.github/workflows/x.yml@refs/heads/main')).toBe(true)
    expect(isPipelineDefinition('github', 'a/b/x.yml')).toBe(false)
  })
})

describe('verifyCause', () => {
  it('names a blocked private address', () => {
    expect(
      verifyCause('jwks unavailable: discovery: host resolves to a blocked address').kind
    ).toBe('private_address')
  })
  it('names an unreachable provider', () => {
    expect(verifyCause('jwks unavailable: discovery: connection refused').kind).toBe('unreachable')
  })
  it('names both issuers when they differ', () => {
    expect(
      verifyCause(
        'issuer "https://gitlab.example.com" does not match "https://gitlab.example.com/"'
      )
    ).toEqual({
      kind: 'issuer_mismatch',
      token: 'https://gitlab.example.com',
      configured: 'https://gitlab.example.com/',
    })
  })
  it('falls back to other', () => {
    expect(verifyCause('something new').kind).toBe('other')
  })
})

describe('refusal fixes', () => {
  it('offers the exact pipeline file the token named', () => {
    const message =
      'CI token from gitlab.example.com/g/p refused: pipeline definition "gitlab.example.com/g/p//.gitlab-ci.yml@refs/heads/main" is not listed'
    expect(refusedDefinition(message)).toBe(
      'gitlab.example.com/g/p//.gitlab-ci.yml@refs/heads/main'
    )
    expect(refusalFixes({ at: '', reasons: ['workflow_not_allowed'], message })).toEqual([
      { kind: 'addDefinition', value: 'gitlab.example.com/g/p//.gitlab-ci.yml@refs/heads/main' },
    ])
  })
  it('opens the pipeline files when the token named none', () => {
    expect(refusalFixes({ at: '', reasons: ['workflow_not_allowed'] })).toEqual([
      { kind: 'openDefinitions' },
    ])
  })
  it('allows the branch and the project', () => {
    expect(
      refusalFixes({
        at: '',
        reasons: ['ref_not_allowed', 'repository_not_allowed', 'ref_not_protected', 'replay'],
        ref: 'refs/heads/feature/x',
        repository: 'acme/api',
      })
    ).toEqual([
      { kind: 'allowBranch', value: 'feature/x' },
      { kind: 'allowRepository', value: 'acme/api' },
      { kind: 'protectedBranch' },
    ])
  })
})

describe('configNames', () => {
  const c = {
    provider: 'gitlab',
    rules: { owners: ['Acme'], repositories: ['beta/team/**', 'gamma/*'] },
  } as CITrustConfig
  it('matches owners and repository patterns as the server does', () => {
    expect(configNames(c, 'acme/api', 'gitlab')).toBe(true)
    expect(configNames(c, 'beta/team/sub/api')).toBe(true)
    expect(configNames(c, 'gamma/api')).toBe(true)
    expect(configNames(c, 'gamma/sub/api')).toBe(false)
    expect(configNames(c, 'acme/api', 'github')).toBe(false)
    expect(configNames(c, '')).toBe(false)
  })
})

describe('private address help', () => {
  const t = ((_k: string, fallback: string) => fallback) as Parameters<typeof privateAllowText>[0]

  it('points at the console page once the API serves its route, else the server setting', () => {
    expect(privateRangesInConsole(['GET /api/v1/ci/runs'])).toBe(false)
    expect(privateRangesInConsole(['GET /api/v1/private-destinations'])).toBe(false)
    expect(privateRangesInConsole(['GET /api/v1/admin/network/private-destinations'])).toBe(true)
    expect(privateAllowText(t, false)).toMatch(/platform administrator can allow it/)
    expect(privateAllowText(t, false)).toContain('OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS')
    expect(privateAllowText(t, true)).toContain('platform console')
    expect(privateAllowText(t, true)).not.toContain('OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS')
  })
})
