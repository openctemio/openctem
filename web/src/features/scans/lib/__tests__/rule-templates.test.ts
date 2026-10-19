import { describe, expect, it } from 'vitest'
import { templateTypeForScanner } from '../rule-templates'

describe('templateTypeForScanner', () => {
  it.each([
    ['nuclei', 'nuclei'],
    ['semgrep', 'semgrep'],
    ['opengrep', 'semgrep'],
    ['betterleaks', 'betterleaks'],
    ['gitleaks', 'betterleaks'],
    ['Nuclei', 'nuclei'],
  ])('%s reads %s templates', (scanner, type) => {
    expect(templateTypeForScanner(scanner)).toBe(type)
  })

  it.each(['trivy', 'tenable_sc', 'subfinder', '', undefined])('%s takes none', (scanner) => {
    expect(templateTypeForScanner(scanner)).toBeNull()
  })
})
