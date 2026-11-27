import { describe, expect, it } from 'vitest'
import { resolveScmProvider, scmProviderFromHost } from './scm-provider'

describe('scmProviderFromHost', () => {
  it.each([
    ['gitlab.example.com/group/repo', 'gitlab'],
    ['https://gitlab.com/group/sub/repo', 'gitlab'],
    ['github.com/org/repo', 'github'],
    ['git@github.com:org/repo.git', 'github'],
    ['https://bitbucket.org/org/repo', 'bitbucket'],
    ['bitbucket.example.com/org/repo', 'bitbucket'],
    ['dev.azure.com/org/proj/_git/repo', 'azure_devops'],
  ])('%s -> %s', (value, want) => {
    expect(scmProviderFromHost(value)).toBe(want)
  })

  it('does not guess for an unknown host or empty value', () => {
    expect(scmProviderFromHost('git.example.com/org/repo')).toBeNull()
    expect(scmProviderFromHost('')).toBeNull()
    expect(scmProviderFromHost(undefined)).toBeNull()
  })
})

describe('resolveScmProvider', () => {
  it('prefers the stored provider', () => {
    expect(resolveScmProvider({ scmProvider: 'bitbucket', hosts: ['gitlab.com/a/b'] })).toBe(
      'bitbucket'
    )
  })
  it('derives from the first recognisable host when none is stored', () => {
    expect(resolveScmProvider({ hosts: [undefined, 'gitlab.example.com/a/b'] })).toBe('gitlab')
  })
  it('is null, never github, when nothing says', () => {
    expect(resolveScmProvider({ hosts: ['git.example.com/a/b'] })).toBeNull()
    expect(resolveScmProvider({ scmProvider: '' })).toBeNull()
  })
})
