import { describe, it, expect } from 'vitest'
import { isCodeLine, segmentScannerText, type ScannerTextBlock } from '../scanner-text'

type Code = Extract<ScannerTextBlock, { kind: 'code' }>
const codes = (blocks: ScannerTextBlock[]) => blocks.filter((b): b is Code => b.kind === 'code')
const kinds = (blocks: ScannerTextBlock[]) =>
  blocks.map((b) => (b.kind === 'prose' ? 'prose' : `${b.role}:${b.language}`))

// The shape of a benchmark audit step as scanners send it (plain text).
const CIS_AUDIT = `Run the following script to verify the pam_faillock.so lines exist in the profile templates:

#!/usr/bin/env bash

{
   l_pam_profile="$(head -1 /etc/authselect/authselect.conf)"
   if grep -Pq -- '^custom\\/' <<< "$l_pam_profile"; then
      l_pam_profile_path="/etc/authselect/$l_pam_profile"
   else
      l_pam_profile_path="/usr/share/authselect/default/$l_pam_profile"
   fi

   grep -P -- '\\bpam_faillock\\.so\\b' "$l_pam_profile_path"/{password,system}-auth
}

Output should be similar to:

/etc/authselect/custom/custom-profile/password-auth:auth required pam_faillock.so preauth silent
/etc/authselect/custom/custom-profile/system-auth:auth required pam_faillock.so authfail

If the lines are missing, the profile must be updated.`

describe('segmentScannerText', () => {
  it('keeps plain prose as one prose block', () => {
    const b = segmentScannerText(
      'The pam_faillock.so module maintains a list of failed attempts.\nLocking accounts slows guessing.'
    )
    expect(kinds(b)).toEqual(['prose'])
  })

  it('splits a benchmark step into prose, a script, its example output and prose', () => {
    const b = segmentScannerText(CIS_AUDIT)
    expect(kinds(b)).toEqual(['prose', 'script:shell', 'prose', 'output:text', 'prose'])
    const [script, output] = codes(b)
    // The whole script, blank line and braces included, is one block.
    expect(script.code.startsWith('#!/usr/bin/env bash')).toBe(true)
    expect(script.code).toContain('fi\n\n   grep -P')
    expect(script.code.trimEnd().endsWith('}')).toBe(true)
    // The output is never offered as a command.
    expect(output.code).toBe(
      '/etc/authselect/custom/custom-profile/password-auth:auth required pam_faillock.so preauth silent\n/etc/authselect/custom/custom-profile/system-auth:auth required pam_faillock.so authfail'
    )
    expect((b[4] as { text: string }).text).toBe(
      'If the lines are missing, the profile must be updated.'
    )
  })

  it('splits $ prompts into commands and what they printed, and Copy drops the prompts', () => {
    const b = segmentScannerText(
      'Check the setting:\n\n$ sysctl net.ipv4.ip_forward\nnet.ipv4.ip_forward = 0\n$ grep -i permitrootlogin /etc/ssh/sshd_config\nPermitRootLogin no'
    )
    expect(kinds(b)).toEqual([
      'prose',
      'command:shell',
      'output:text',
      'command:shell',
      'output:text',
    ])
    const [cmd1, out1] = codes(b)
    expect(cmd1.code).toBe('$ sysctl net.ipv4.ip_forward')
    expect(cmd1.copyText).toBe('sysctl net.ipv4.ip_forward')
    expect(out1.code).toBe('net.ipv4.ip_forward = 0')
  })

  it('treats a root prompt "# cmd" as a command, not a heading', () => {
    const b = segmentScannerText('Run:\n# systemctl restart sshd')
    expect(codes(b)[0]).toMatchObject({ role: 'command', copyText: 'systemctl restart sshd' })
  })

  it('treats an indented block as code and removes the common indent', () => {
    const b = segmentScannerText(
      'Edit the file:\n\n    PermitRootLogin no\n    MaxAuthTries 4\n\nThen restart.'
    )
    expect(kinds(b)).toEqual(['prose', 'command:shell', 'prose'])
    expect(codes(b)[0].code).toBe('PermitRootLogin no\nMaxAuthTries 4')
  })

  it('keeps a fenced block as the author marked it', () => {
    const b = segmentScannerText('Apply:\n```bash\necho "x" > /etc/issue\n```\nDone.')
    expect(kinds(b)).toEqual(['prose', 'code:shell', 'prose'])
    expect(codes(b)[0].code).toBe('echo "x" > /etc/issue')
  })

  it('does not take a sentence that starts with a capitalised command word as code', () => {
    expect(isCodeLine('Find the file and remove the line.')).toBe(false)
    expect(isCodeLine('Set the parameter in the configuration.')).toBe(false)
    expect(isCodeLine('find / -xdev -type f -perm -0002')).toBe(true)
    expect(isCodeLine('chmod 600 /etc/ssh/sshd_config')).toBe(true)
    expect(isCodeLine('Set-ItemProperty -Path HKLM:\\x -Name y -Value 1')).toBe(true)
  })

  it('returns nothing for empty text', () => {
    expect(segmentScannerText('')).toEqual([])
    expect(segmentScannerText('\n\n')).toEqual([])
  })
})
