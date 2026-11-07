/**
 * Splits scanner-supplied prose (a description, a remediation, a CIS
 * benchmark's audit and fix steps) into prose and code blocks, so a script
 * or a command reads as code instead of a wall of text.
 *
 * Scanner text is untrusted and is rarely markdown: scripts arrive as plain
 * lines (a shebang, an indented body, `$ ` prompts, shell keywords), often
 * followed by an "example output" the reader must not paste into a shell.
 * The detection here only decides the layout; every block is still rendered
 * as text (see ScannerText), never as HTML.
 */

export type ScannerCodeLanguage = 'shell' | 'text'

/**
 * - `script`: a multi-line program (a shebang, a body in braces);
 * - `command`: one or more commands to run (prompts already stripped for Copy);
 * - `output`: what a command prints, shown apart and never offered as a command;
 * - `code`: a fenced block the author marked as code.
 */
export type ScannerCodeRole = 'script' | 'command' | 'output' | 'code'

export type ScannerTextBlock =
  | { kind: 'prose'; text: string }
  | {
      kind: 'code'
      code: string
      language: ScannerCodeLanguage
      role: ScannerCodeRole
      /** What Copy puts on the clipboard: the commands without their prompts. */
      copyText: string
    }

// Commands and shell words a scanner's fix or audit step starts with. Lower
// case only: a sentence starts with a capital ("Find the file"), a command
// does not.
const SHELL_WORDS = new Set([
  'if',
  'then',
  'else',
  'elif',
  'fi',
  'for',
  'while',
  'until',
  'do',
  'done',
  'case',
  'esac',
  'function',
  'return',
  'exit',
  'export',
  'local',
  'declare',
  'readonly',
  'unset',
  'source',
  'echo',
  'printf',
  'grep',
  'egrep',
  'sed',
  'awk',
  'cat',
  'head',
  'tail',
  'find',
  'xargs',
  'chmod',
  'chown',
  'chgrp',
  'systemctl',
  'service',
  'sysctl',
  'modprobe',
  'lsmod',
  'mount',
  'umount',
  'findmnt',
  'rm',
  'mv',
  'cp',
  'mkdir',
  'touch',
  'ln',
  'ls',
  'stat',
  'test',
  'readlink',
  'tee',
  'apt',
  'apt-get',
  'yum',
  'dnf',
  'zypper',
  'rpm',
  'dpkg',
  'snap',
  'auditctl',
  'augenrules',
  'authselect',
  'ufw',
  'iptables',
  'ip6tables',
  'nft',
  'firewall-cmd',
  'sudo',
  'useradd',
  'usermod',
  'userdel',
  'groupadd',
  'passwd',
  'chage',
  'crontab',
  'sshd',
  'ps',
  'kill',
  'journalctl',
  'getenforce',
  'setenforce',
  'semanage',
  'restorecon',
  'update-crypto-policies',
  'grub2-mkconfig',
  'grub2-setpassword',
  'update-grub',
  'dconf',
  'gsettings',
  'aide',
  'openssl',
  'curl',
  'wget',
  'net',
  'reg',
  'auditpol',
  'secedit',
  'powershell',
])

const SHEBANG = /^#!\//
// "$ cmd" or a root prompt "# cmd" (lower-case command, not a heading).
const PROMPT = /^\s*(?:\$|#)\s+(?=[a-z.\/~[{(])/
const FENCE = /^\s*(```|~~~)\s*([\w+-]*)\s*$/
const INDENTED = /^(?: {4}|\t)\S?/
const STRUCTURE = /^\s*(?:[{}()]|;;|\}\s*(?:else|elif)\b.*)\s*;?\s*$/
const ASSIGNMENT = /^\s*(?:export\s+|local\s+|readonly\s+)?[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?=\S/
const ABSOLUTE_PATH = /^\s*(?:\/[\w.@-]+){2,}/
const REGISTRY = /^\s*(?:HKLM|HKCU|HKEY_[A-Z_]+)\\/
const POWERSHELL = /^\s*[A-Z][a-z]+-[A-Z][A-Za-z]+(?:\s|$)/
const OUTPUT_INTRO =
  /(?:\boutput\b[^.]*:\s*$|\b(?:should|will|must)\s+(?:be\s+)?(?:similar\s+to|look\s+like|return|show|resemble)\b[^.]*:?\s*$|\breturns?\s*:\s*$|\bsimilar\s+to\s*:?\s*$)/i
const FENCE_SHELL = new Set([
  'sh',
  'bash',
  'shell',
  'zsh',
  'console',
  'shell-session',
  'ps1',
  'powershell',
])

function firstWord(line: string): string {
  const m = /^\s*([A-Za-z0-9_][\w.-]*)/.exec(line)
  return m ? m[1] : ''
}

/** True when the line reads as code (a command, a script line, a path). */
export function isCodeLine(line: string): boolean {
  if (!line.trim()) return false
  if (SHEBANG.test(line) || PROMPT.test(line) || INDENTED.test(line)) return true
  if (STRUCTURE.test(line) || ASSIGNMENT.test(line)) return true
  if (ABSOLUTE_PATH.test(line) || REGISTRY.test(line) || POWERSHELL.test(line)) return true
  const word = firstWord(line)
  if (!SHELL_WORDS.has(word)) return false
  // A command word that ends the line, or is followed by an option, a path,
  // a quote, a variable, or a pipe-like shape: "grep -P", "echo \"…\"".
  const rest = line.trim().slice(word.length)
  if (rest === '' || /^[;&|]/.test(rest)) return true
  if (/^\s+(?:-|\/|"|'|\$|~|\.|\[|\{|\(|\w+=)/.test(rest)) return true
  // An argument anywhere that is an option, a path, a number or a variable.
  if (/\s(?:-{1,2}[\w-]|\/[\w.]|~\/|\d+(?:\s|$)|\$)/.test(rest)) return true
  // Shell syntax anywhere on the line: a pipe, a redirect, &&, $(…), a
  // trailing ; or \.
  return /(?:\s\|\s|\s>>?\s|&&|\$\(|;\s*$|\\\s*$|\s-[A-Za-z]{1,3}\b)/.test(rest)
}

function braceDelta(line: string): number {
  // Braces that open or close a block, not ${var} or "{…}" in a string.
  const bare = line.replace(/"(?:\\.|[^"\\])*"|'[^']*'/g, '').replace(/\$\{[^}]*\}/g, '')
  let d = 0
  for (const ch of bare) {
    if (ch === '{') d++
    else if (ch === '}') d--
  }
  return d
}

function dedent(lines: string[]): string[] {
  let min = Infinity
  for (const l of lines) {
    if (!l.trim()) continue
    const lead = /^[ \t]*/.exec(l)![0].replace(/\t/g, '    ').length
    if (lead < min) min = lead
  }
  if (!Number.isFinite(min) || min === 0) return lines
  return lines.map((l) => {
    let cut = 0
    let width = 0
    while (cut < l.length && width < min && (l[cut] === ' ' || l[cut] === '\t')) {
      width += l[cut] === '\t' ? 4 : 1
      cut++
    }
    return l.slice(cut)
  })
}

function trimBlank(lines: string[]): string[] {
  let a = 0
  let b = lines.length
  while (a < b && !lines[a].trim()) a++
  while (b > a && !lines[b - 1].trim()) b--
  return lines.slice(a, b)
}

function stripPrompt(line: string): string {
  return line.replace(/^\s*(?:\$|#)\s+/, '')
}

/** Splits a run of code lines by its prompts: command lines, then what they printed. */
function codeBlocks(raw: string[], afterOutputIntro: boolean): ScannerTextBlock[] {
  const lines = dedent(trimBlank(raw))
  if (lines.length === 0) return []
  const code = lines.join('\n')
  if (afterOutputIntro && !lines.some((l) => PROMPT.test(l) && !SHEBANG.test(l))) {
    return [{ kind: 'code', code, language: 'text', role: 'output', copyText: code }]
  }
  if (SHEBANG.test(lines[0])) {
    return [{ kind: 'code', code, language: 'shell', role: 'script', copyText: code }]
  }
  const prompted = lines.some((l) => PROMPT.test(l))
  if (!prompted) {
    const multi = lines.filter((l) => l.trim()).length > 1 && lines.some((l) => braceDelta(l) !== 0)
    return [
      { kind: 'code', code, language: 'shell', role: multi ? 'script' : 'command', copyText: code },
    ]
  }
  // "$ cmd" lines are commands; the lines under them are their output.
  const out: ScannerTextBlock[] = []
  let cmds: string[] = []
  let printed: string[] = []
  const flush = () => {
    if (cmds.length) {
      out.push({
        kind: 'code',
        code: cmds.join('\n'),
        language: 'shell',
        role: 'command',
        copyText: cmds.map(stripPrompt).join('\n'),
      })
      cmds = []
    }
    const p = trimBlank(printed)
    if (p.length) {
      const text = p.join('\n')
      out.push({ kind: 'code', code: text, language: 'text', role: 'output', copyText: text })
    }
    printed = []
  }
  for (const l of lines) {
    if (PROMPT.test(l)) {
      if (printed.some((p) => p.trim())) flush()
      cmds.push(l)
    } else if (cmds.length === 0 && printed.length === 0) {
      // Lines before the first prompt are commands too (a continuation).
      cmds.push(l)
    } else {
      printed.push(l)
    }
  }
  flush()
  return out
}

/** Splits scanner text into prose and code blocks (see the file comment). */
export function segmentScannerText(input: string): ScannerTextBlock[] {
  const lines = (input ?? '').replace(/\r\n?/g, '\n').split('\n')
  const blocks: ScannerTextBlock[] = []
  let prose: string[] = []
  let code: string[] = []
  let depth = 0
  let script = false
  let lastProse = ''

  const flushProse = () => {
    const p = trimBlank(prose)
    if (p.length) {
      blocks.push({ kind: 'prose', text: p.join('\n') })
      const last = p.filter((l) => l.trim()).pop()
      lastProse = last ?? lastProse
    }
    prose = []
  }
  const flushCode = () => {
    if (code.length) {
      blocks.push(...codeBlocks(code, OUTPUT_INTRO.test(lastProse.trim())))
      lastProse = ''
    }
    code = []
    depth = 0
    script = false
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]

    // A fenced block the author marked: kept as is.
    const fence = FENCE.exec(line)
    if (fence && code.length === 0) {
      const close = lines.findIndex((l, j) => j > i && l.trim().startsWith(fence[1]))
      if (close !== -1) {
        flushProse()
        const body = lines.slice(i + 1, close).join('\n')
        const lang = fence[2].toLowerCase()
        const output = OUTPUT_INTRO.test(lastProse.trim()) || lang === 'text' || lang === 'output'
        blocks.push({
          kind: 'code',
          code: body,
          language: FENCE_SHELL.has(lang) || (!lang && !output) ? 'shell' : 'text',
          role: output ? 'output' : 'code',
          copyText: body,
        })
        lastProse = ''
        i = close
        continue
      }
    }

    const blank = !line.trim()
    if (code.length > 0) {
      // Inside a code run: a script body (open braces, after a shebang)
      // keeps going; otherwise blank lines continue it only when code
      // follows them.
      if (blank) {
        code.push(line)
        continue
      }
      const inside = depth > 0 || (script && !/^[A-Z][a-z]/.test(line))
      // What a "$ cmd" printed: the lines right under it, up to a blank line.
      const printed = code.some((l) => PROMPT.test(l)) && !!code[code.length - 1].trim()
      const outputRun =
        OUTPUT_INTRO.test(lastProse.trim()) && !/^[A-Z][a-z]+\s+\w+\s+\w+/.test(line)
      if (inside || printed || isCodeLine(line) || outputRun) {
        code.push(line)
        depth = Math.max(0, depth + braceDelta(line))
        continue
      }
      flushCode()
    }

    if (
      !blank &&
      (isCodeLine(line) || (OUTPUT_INTRO.test(lastProse.trim()) && prose.every((p) => !p.trim())))
    ) {
      // Code starts; an output intro makes the next lines output whatever
      // they look like.
      flushProse()
      code.push(line)
      script = SHEBANG.test(line)
      depth = Math.max(0, braceDelta(line))
      continue
    }

    prose.push(line)
    if (!blank) lastProse = line
  }
  flushProse()
  flushCode()
  return blocks
}
