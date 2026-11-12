'use client'

/**
 * The one renderer for scanner-supplied prose: a finding's description,
 * remediation and solution text, a benchmark's audit and fix steps.
 *
 * The text is untrusted (whoever controls a scanned host or a scanner's
 * plugin feed shapes it), so:
 *
 * - prose is markdown WITHOUT raw HTML: an HTML tag in the text is shown as
 *   the characters it is (never parsed, never dropped silently);
 * - links go through SafeExternalLink (http and https only, no relative
 *   paths into the console, a new tab, rel="noopener noreferrer nofollow");
 * - images are never loaded (a markdown image becomes its alt text), so the
 *   text cannot plant a tracking pixel or a fake screenshot;
 * - headings render as bold paragraphs (a "# comment" cannot take the page);
 * - control and bidi characters are visible escapes (toDisplayBlock);
 * - scripts and commands (segmentScannerText) render as UntrustedTextBlock
 *   code blocks with shell highlighting, Copy and "Show more", and what a
 *   command prints is shown apart as "Example output".
 *
 * Nothing is injected as HTML and no raw-HTML plugin runs: the scanner-text
 * XSS test renders hostile text through this component.
 */

import * as React from 'react'
import Markdown, { type Components } from 'react-markdown'
import { useTranslation } from '@/context/i18n-provider'
import { SafeExternalLink } from '@/components/safe-external-link'
import { segmentScannerText, type ScannerTextBlock } from '@/lib/scanner-text'
import { toDisplayBlock } from '@/lib/untrusted-text'
import { cn } from '@/lib/utils'
import { UntrustedTextBlock } from './untrusted-text-block'

/** Lines of a code block shown before "Show more". */
export const SCANNER_CODE_LINES = 12

interface MdNode {
  type: string
  value?: string
  children?: MdNode[]
}

/** Remark plugin: raw HTML (block or inline) becomes plain text. */
function remarkHtmlAsText() {
  const walk = (node: MdNode) => {
    if (node.type === 'html') node.type = 'text'
    node.children?.forEach(walk)
  }
  return (tree: MdNode) => walk(tree)
}

const REMARK_PLUGINS = [remarkHtmlAsText]

function Heading({ children }: { children?: React.ReactNode }) {
  return <p className="font-semibold">{children}</p>
}

const MARKDOWN_COMPONENTS: Components = {
  p: ({ children }) => <p className="whitespace-pre-line">{children}</p>,
  h1: Heading,
  h2: Heading,
  h3: Heading,
  h4: Heading,
  h5: Heading,
  h6: Heading,
  a: ({ href, children }) => (
    <SafeExternalLink
      href={href}
      urlOptions={{ allowRelative: false }}
      className="underline underline-offset-2 hover:text-foreground"
    >
      {children}
    </SafeExternalLink>
  ),
  // Never load an image the scanner names: show its alt text.
  img: ({ alt }) => (alt ? <span>{alt}</span> : null),
  ul: ({ children }) => <ul className="list-disc space-y-1 ps-5">{children}</ul>,
  ol: ({ children }) => <ol className="list-decimal space-y-1 ps-5">{children}</ol>,
  code: ({ children }) => (
    <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs text-foreground">
      {children}
    </code>
  ),
  // A code block that reaches markdown (an indented line inside a list) is
  // still escaped text.
  pre: ({ children }) => (
    <pre className="rounded-md border bg-muted/40 p-3 font-mono text-xs whitespace-pre-wrap">
      {children}
    </pre>
  ),
  blockquote: ({ children }) => (
    <blockquote className="ps-3 text-muted-foreground">{children}</blockquote>
  ),
  hr: () => <hr className="border-border" />,
}

/** Keeps the link text and drops every URL that is not http(s) or mailto. */
function urlTransform(url: string): string {
  return /^(?:https?:|mailto:)/i.test(url.trim()) ? url : ''
}

function Prose({ text }: { text: string }) {
  return (
    <div className="space-y-2 text-sm leading-relaxed [overflow-wrap:anywhere]" dir="auto">
      <Markdown
        remarkPlugins={REMARK_PLUGINS}
        components={MARKDOWN_COMPONENTS}
        urlTransform={urlTransform}
      >
        {toDisplayBlock(text)}
      </Markdown>
    </div>
  )
}

function CodeBlock({ block }: { block: Extract<ScannerTextBlock, { kind: 'code' }> }) {
  const { t } = useTranslation()
  const caption =
    block.role === 'output'
      ? t('components.scannerText.exampleOutput', 'Example output')
      : block.role === 'script'
        ? t('components.scannerText.script', 'Script')
        : block.role === 'command'
          ? t('components.scannerText.command', 'Command')
          : undefined
  return (
    <UntrustedTextBlock
      text={block.code}
      copyText={block.copyText}
      language={block.language}
      caption={caption}
      label={caption ?? t('components.scannerText.code', 'Code')}
      collapseLines={SCANNER_CODE_LINES}
    />
  )
}

export interface ScannerTextProps {
  text: string
  className?: string
  /**
   * Show a short preview (about eight lines) with "Show more", for a drawer
   * or a card where the text is one section among many.
   */
  preview?: boolean
}

export function ScannerText({ text, className, preview }: ScannerTextProps) {
  const { t } = useTranslation()
  const [open, setOpen] = React.useState(false)
  const blocks = React.useMemo(() => segmentScannerText(text), [text])
  const long = !!preview && (text.length > 600 || text.split('\n').length > 8)
  if (blocks.length === 0) return null
  return (
    <div className={cn('min-w-0', className)} data-slot="scanner-text">
      <div
        className={cn('space-y-3', long && !open && 'max-h-44 overflow-hidden')}
        data-collapsed={long && !open ? '' : undefined}
      >
        {blocks.map((b, i) =>
          b.kind === 'prose' ? <Prose key={i} text={b.text} /> : <CodeBlock key={i} block={b} />
        )}
      </div>
      {long && (
        <button
          type="button"
          className="mt-1 rounded-sm text-xs font-medium text-muted-foreground hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          aria-expanded={open}
          onClick={() => setOpen((v) => !v)}
        >
          {open
            ? t('components.scannerText.showLess', 'Show less')
            : t('components.scannerText.showMore', 'Show more')}
        </button>
      )}
    </div>
  )
}
