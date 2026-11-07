'use client'

import { useMemo, useState } from 'react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { toDisplayBlock } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'
import { TOKEN_COLORS, tokenize } from '@/lib/code-tokens'

// Language detection based on file extension
function detectLanguage(filePath?: string): string {
  if (!filePath) return 'text'
  const ext = filePath.split('.').pop()?.toLowerCase()

  const languageMap: Record<string, string> = {
    // Go
    go: 'go',
    // TypeScript/JavaScript
    ts: 'typescript',
    tsx: 'typescript',
    js: 'javascript',
    jsx: 'javascript',
    mjs: 'javascript',
    cjs: 'javascript',
    // Python
    py: 'python',
    pyw: 'python',
    // Java/Kotlin
    java: 'java',
    kt: 'kotlin',
    kts: 'kotlin',
    // C/C++
    c: 'c',
    h: 'c',
    cpp: 'cpp',
    hpp: 'cpp',
    cc: 'cpp',
    cxx: 'cpp',
    // Rust
    rs: 'rust',
    // Ruby
    rb: 'ruby',
    // PHP
    php: 'php',
    // SQL
    sql: 'sql',
    // Shell
    sh: 'shell',
    bash: 'shell',
    zsh: 'shell',
    // YAML/JSON
    yaml: 'yaml',
    yml: 'yaml',
    json: 'json',
    // HTML/CSS
    html: 'html',
    htm: 'html',
    css: 'css',
    scss: 'css',
    // Terraform
    tf: 'terraform',
    tfvars: 'terraform',
    // Solidity
    sol: 'solidity',
  }

  return languageMap[ext || ''] || 'text'
}

interface CodeHighlighterProps {
  code: string
  filePath?: string
  className?: string
  showLineNumbers?: boolean
  startLine?: number
  highlightLine?: number
}

function CodeBlock({
  code,
  filePath,
  className,
  showLineNumbers = false,
  startLine = 1,
  highlightLine,
}: CodeHighlighterProps) {
  const language = detectLanguage(filePath)

  const highlighted = useMemo(() => {
    const tokens = tokenize(code, language)
    return tokens.map((token, i) => (
      <span key={i} className={TOKEN_COLORS[token.type]}>
        {token.value}
      </span>
    ))
  }, [code, language])

  if (showLineNumbers) {
    const lines = code.split('\n')
    return (
      <pre className={cn('text-xs font-mono overflow-x-auto', className)}>
        <code className="block">
          {lines.map((line, i) => {
            const lineNumber = startLine + i
            const isHighlighted = lineNumber === highlightLine
            const lineTokens = tokenize(line, language)

            return (
              <div key={i} className={cn('flex', isHighlighted && 'bg-yellow-500/20 -mx-3 px-3')}>
                <span className="select-none w-8 text-end pe-3 text-slate-600 flex-shrink-0">
                  {lineNumber}
                </span>
                <span className="flex-1">
                  {lineTokens.map((token, j) => (
                    <span key={j} className={TOKEN_COLORS[token.type]}>
                      {token.value}
                    </span>
                  ))}
                </span>
              </div>
            )
          })}
        </code>
      </pre>
    )
  }

  return (
    <pre
      className={cn('text-xs font-mono overflow-x-auto whitespace-pre-wrap break-all', className)}
    >
      <code>{highlighted}</code>
    </pre>
  )
}

/** Characters shown before "Show more"; the rest is capped by `toDisplayBlock`. */
export const CODE_PREVIEW_CHARS = 20_000

/**
 * Scanner-supplied code (snippets, stack frames, data-flow steps) is
 * attacker-influenced: bidi and control characters are shown as visible
 * escapes (a Trojan-Source line cannot reorder what the reader sees), and a
 * huge snippet is cut with a "Show more" instead of freezing the tab.
 */
export function CodeHighlighter(props: CodeHighlighterProps) {
  const { t } = useTranslation()
  const [expanded, setExpanded] = useState(false)
  const raw = props.code ?? ''
  const truncated = !expanded && raw.length > CODE_PREVIEW_CHARS
  const code = useMemo(
    () => toDisplayBlock(truncated ? raw.slice(0, CODE_PREVIEW_CHARS) : raw),
    [raw, truncated]
  )
  return (
    <>
      <CodeBlock {...props} code={code} />
      {truncated && (
        <Button
          variant="link"
          size="sm"
          className="mt-1 h-auto p-0 text-xs"
          onClick={() => setExpanded(true)}
        >
          {t('findings.code.showMore', 'Show more')}
        </Button>
      )}
    </>
  )
}

// Export language detection for external use
export { detectLanguage }
