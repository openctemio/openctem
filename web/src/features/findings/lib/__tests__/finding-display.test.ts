import { describe, expect, it } from 'vitest'
import { displayTitle, userTags } from '../finding-display'

const sca = (title: string, pkg?: string) =>
  displayTitle({
    title,
    source: 'sca',
    component: pkg ? { name: pkg, version: '1', ecosystem: 'pypi' } : undefined,
  })

describe('displayTitle', () => {
  it('drops a package prefix the title repeats', () => {
    expect(sca('django: Django SQL injection', 'Django')).toBe('Django SQL injection')
    expect(sca('Django: Django: SQL Injection via crafted column aliases', 'Django')).toBe(
      'SQL Injection via crafted column aliases in Django'
    )
  })
  it('moves the package to the end when the rest does not name it', () => {
    expect(sca('PyYAML: arbitrary command execution', 'PyYAML')).toBe(
      'Arbitrary command execution in PyYAML'
    )
    expect(sca('python-jinja2: str.format allows a sandbox escape', 'Jinja2')).toBe(
      'str.format allows a sandbox escape in Jinja2'
    )
  })
  it('keeps a prefix that is another package', () => {
    expect(sca('express: "qs" prototype poisoning', 'qs')).toBe('express: "qs" prototype poisoning')
    expect(sca('Plain title', 'x')).toBe('Plain title')
  })
  it('names a secret by its kind and file', () => {
    expect(
      displayTitle({
        title:
          'Detected a Generic API Key, potentially exposing access to various services and sensitive operations.',
        source: 'secret',
        filePath: 'app/settings.py',
      })
    ).toBe('Generic API Key in app/settings.py')
  })
  it('uses the SAST message instead of a rule slug', () => {
    expect(
      displayTitle({
        title: 'Flask Request To Sink',
        ruleName: 'Flask Request To Sink',
        source: 'sast',
        message: 'Request data reaches a command or a query. More text.',
      })
    ).toBe('Request data reaches a command or a query')
  })
})

describe('userTags', () => {
  it('drops the scanner artefacts', () => {
    expect(
      userTags({
        tags: ['trivy', 'app/requirements.txt', 'secret', 'payments', 'pci'],
        toolName: 'trivy',
        filePath: 'app/requirements.txt',
        source: 'sca',
      })
    ).toEqual(['payments', 'pci'])
  })
})
