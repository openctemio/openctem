'use client'

/**
 * Markdown editor: a plain auto-growing textarea with a one-row toolbar and a
 * Write / Preview switch.
 *
 * - The toolbar never wraps: the buttons that do not fit the width move into
 *   a "More" menu (measured with a ResizeObserver).
 * - Formatting goes through the browser's insertText, so Ctrl+Z works.
 * - With `onUploadFile`, pasted or dropped files are uploaded and inserted as
 *   markdown at the caret, with a progress line per file.
 * - Preview renders through MarkdownPreview, which sanitises the output
 *   (see @/lib/sanitize-markdown); code blocks are syntax highlighted.
 */

import * as React from 'react'
import dynamic from 'next/dynamic'
import { useTheme } from 'next-themes'
import {
  Bold,
  Code,
  Ellipsis,
  Heading,
  Image as ImageIcon,
  Italic,
  Link as LinkIcon,
  List,
  ListChecks,
  ListOrdered,
  Loader2,
  Minus,
  Quote,
  SquareCode,
  Strikethrough,
  Table as TableIcon,
  type LucideIcon,
} from 'lucide-react'
import { toast } from 'sonner'
import { cn } from '@/lib/utils'
import { markdownPreviewSecurityProps } from '@/lib/sanitize-markdown'
import { useTranslation } from '@/context/i18n-provider'
import {
  applyEdit,
  applyMarkdownCommand,
  type MarkdownCommandId,
  type MarkdownEdit,
} from '@/lib/markdown-commands'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'

/** Uploads one file and resolves to the markdown that shows or links it. */
export type MarkdownUploadHandler = (
  file: File,
  onProgress: (fraction: number) => void
) => Promise<string>

export interface MarkdownEditorProps {
  value: string
  onChange: (value: string) => void
  placeholder?: string
  /** Minimum height of the writing area, in pixels. It grows with the text. */
  height?: number
  /** Height after which the writing area scrolls instead of growing. */
  maxHeight?: number
  className?: string
  hideToolbar?: boolean
  id?: string
  'aria-label'?: string
  'aria-describedby'?: string
  invalid?: boolean
  /** Shows a character counter once the text passes 80% of this length. */
  maxLength?: number
  /** Enables pasting and dropping files (images, logs) into the text. */
  onUploadFile?: MarkdownUploadHandler
  autoFocus?: boolean
}

interface CommandDef {
  id: MarkdownCommandId
  icon: LucideIcon
  labelKey: string
  label: string
  shortcut?: string
}

// Ordered by how often authors reach for them: the first ones stay visible on
// narrow widths, the rest move into "More".
const COMMANDS: CommandDef[] = [
  { id: 'bold', icon: Bold, labelKey: 'bold', label: 'Bold', shortcut: 'B' },
  { id: 'italic', icon: Italic, labelKey: 'italic', label: 'Italic', shortcut: 'I' },
  { id: 'code', icon: Code, labelKey: 'code', label: 'Inline code', shortcut: 'E' },
  { id: 'codeBlock', icon: SquareCode, labelKey: 'codeBlock', label: 'Code block' },
  { id: 'link', icon: LinkIcon, labelKey: 'link', label: 'Link', shortcut: 'K' },
  { id: 'bulletList', icon: List, labelKey: 'bulletList', label: 'Bulleted list' },
  { id: 'numberedList', icon: ListOrdered, labelKey: 'numberedList', label: 'Numbered list' },
  { id: 'quote', icon: Quote, labelKey: 'quote', label: 'Quote' },
  { id: 'image', icon: ImageIcon, labelKey: 'image', label: 'Image' },
  { id: 'heading', icon: Heading, labelKey: 'heading', label: 'Heading' },
  { id: 'strike', icon: Strikethrough, labelKey: 'strike', label: 'Strikethrough' },
  { id: 'checklist', icon: ListChecks, labelKey: 'checklist', label: 'Checklist' },
  { id: 'table', icon: TableIcon, labelKey: 'table', label: 'Table' },
  { id: 'hr', icon: Minus, labelKey: 'hr', label: 'Horizontal rule' },
]

const SHORTCUT_COMMANDS: Record<string, MarkdownCommandId> = {
  b: 'bold',
  i: 'italic',
  e: 'code',
  k: 'link',
}

/** Toolbar button width (h-7 w-7) plus its gap, in pixels. */
const BUTTON_SLOT = 30

interface Upload {
  key: string
  name: string
  progress: number
}

let uploadSeq = 0

export function MarkdownEditor({
  value,
  onChange,
  placeholder,
  height = 120,
  maxHeight = 640,
  className,
  hideToolbar = false,
  id,
  'aria-label': ariaLabel,
  'aria-describedby': ariaDescribedBy,
  invalid = false,
  maxLength,
  onUploadFile,
  autoFocus,
}: MarkdownEditorProps) {
  const { t } = useTranslation()
  const [mode, setMode] = React.useState<'write' | 'preview'>('write')
  const [uploads, setUploads] = React.useState<Upload[]>([])
  const [dragging, setDragging] = React.useState(false)
  const [visibleCount, setVisibleCount] = React.useState(COMMANDS.length)
  const textareaRef = React.useRef<HTMLTextAreaElement>(null)
  const toolbarRef = React.useRef<HTMLDivElement>(null)
  const fileInputRef = React.useRef<HTMLInputElement>(null)
  const generatedId = React.useId()
  const textareaId = id ?? `md-${generatedId}`
  // The latest text, for uploads that finish after more typing.
  const valueRef = React.useRef(value)
  React.useLayoutEffect(() => {
    valueRef.current = value
  }, [value])

  const label = React.useCallback(
    (c: CommandDef) => t(`common.markdownEditor.${c.labelKey}`, c.label),
    [t]
  )

  // Fit as many toolbar buttons as the width allows; the rest go to "More".
  React.useEffect(() => {
    const el = toolbarRef.current
    if (!el || typeof ResizeObserver === 'undefined') return
    const measure = () => {
      const width = el.clientWidth
      if (width <= 0) return
      const all = Math.floor(width / BUTTON_SLOT)
      setVisibleCount(all >= COMMANDS.length ? COMMANDS.length : Math.max(0, all - 1))
    }
    measure()
    const ro = new ResizeObserver(measure)
    ro.observe(el)
    return () => ro.disconnect()
  }, [hideToolbar, mode])

  // Grow the textarea with its content, between `height` and `maxHeight`.
  React.useLayoutEffect(() => {
    const ta = textareaRef.current
    if (!ta || mode !== 'write') return
    ta.style.height = 'auto'
    const next = Math.min(Math.max(ta.scrollHeight, height), maxHeight)
    ta.style.height = `${next}px`
    ta.style.overflowY = ta.scrollHeight > maxHeight ? 'auto' : 'hidden'
  }, [value, height, maxHeight, mode])

  const applyEditToTextarea = React.useCallback(
    (edit: MarkdownEdit) => {
      const ta = textareaRef.current
      const expected = applyEdit(valueRef.current, edit)
      if (ta) {
        ta.focus()
        ta.setSelectionRange(edit.from, edit.to)
        // insertText keeps the browser's undo stack; it fires an input event
        // that reaches onChange. Not every engine supports it (jsdom does not).
        let inserted = false
        try {
          inserted =
            typeof document.execCommand === 'function' &&
            document.execCommand('insertText', false, edit.text)
        } catch {
          inserted = false
        }
        if (inserted && ta.value === expected) {
          valueRef.current = expected
          ta.setSelectionRange(edit.selStart, edit.selEnd)
          return
        }
      }
      valueRef.current = expected
      onChange(expected)
      requestAnimationFrame(() => {
        textareaRef.current?.setSelectionRange(edit.selStart, edit.selEnd)
      })
    },
    [onChange]
  )

  const uploadFiles = React.useCallback(
    (files: File[]) => {
      if (!onUploadFile || files.length === 0) return
      for (const file of files) {
        uploadSeq += 1
        const key = `upload-${uploadSeq}`
        const name = file.name || t('common.markdownEditor.pastedFile', 'pasted file')
        const placeholderText = `![${t('common.markdownEditor.uploadingAlt', 'Uploading {name}…', { name })}](#${key})`
        const ta = textareaRef.current
        const start = ta ? ta.selectionStart : valueRef.current.length
        const end = ta ? ta.selectionEnd : valueRef.current.length
        const lead = start > 0 && valueRef.current[start - 1] !== '\n' ? '\n' : ''
        const text = `${lead}${placeholderText}\n`
        const caret = start + text.length
        applyEditToTextarea({ from: start, to: end, text, selStart: caret, selEnd: caret })
        setUploads((prev) => [...prev, { key, name, progress: 0 }])

        const replacePlaceholder = (replacement: string) => {
          const current = valueRef.current
          const at = current.indexOf(placeholderText)
          if (at === -1) return
          // Drop the newline after the placeholder too when removing it.
          const tail = replacement === '' && current[at + placeholderText.length] === '\n' ? 1 : 0
          const next =
            current.slice(0, at) + replacement + current.slice(at + placeholderText.length + tail)
          valueRef.current = next
          onChange(next)
        }

        onUploadFile(file, (fraction) =>
          setUploads((prev) =>
            prev.map((u) =>
              u.key === key ? { ...u, progress: Math.round(Math.min(1, fraction) * 100) } : u
            )
          )
        )
          .then((markdown) => replacePlaceholder(markdown))
          .catch((err: unknown) => {
            replacePlaceholder('')
            toast.error(
              err instanceof Error && err.message
                ? err.message
                : t('common.markdownEditor.uploadFailed', 'Upload failed: {name}', { name })
            )
          })
          .finally(() => setUploads((prev) => prev.filter((u) => u.key !== key)))
      }
    },
    [onUploadFile, applyEditToTextarea, onChange, t]
  )

  const runCommand = React.useCallback(
    (cmd: MarkdownCommandId) => {
      if (cmd === 'image' && onUploadFile) {
        fileInputRef.current?.click()
        return
      }
      if (mode !== 'write') setMode('write')
      const ta = textareaRef.current
      const sel = {
        value: valueRef.current,
        start: ta?.selectionStart ?? valueRef.current.length,
        end: ta?.selectionEnd ?? valueRef.current.length,
      }
      const edit = applyMarkdownCommand(cmd, sel, {
        text: t('common.markdownEditor.phText', 'text'),
        code: t('common.markdownEditor.phCode', 'code'),
        column: t('common.markdownEditor.phColumn', 'Column'),
      })
      applyEditToTextarea(edit)
    },
    [applyEditToTextarea, mode, onUploadFile, t]
  )

  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (!(e.ctrlKey || e.metaKey) || e.altKey || e.shiftKey) return
    const cmd = SHORTCUT_COMMANDS[e.key.toLowerCase()]
    if (cmd) {
      e.preventDefault()
      runCommand(cmd)
    }
  }

  const filesFrom = (list: FileList | null | undefined) => (list ? Array.from(list) : [])

  const onPaste = (e: React.ClipboardEvent<HTMLTextAreaElement>) => {
    if (!onUploadFile) return
    const files = filesFrom(e.clipboardData?.files)
    if (files.length === 0) return
    e.preventDefault()
    uploadFiles(files)
  }

  const hasFiles = (e: React.DragEvent) => Array.from(e.dataTransfer?.types ?? []).includes('Files')

  const visible = COMMANDS.slice(0, visibleCount)
  const overflow = COMMANDS.slice(visibleCount)
  const count = value.length
  const showCounter = maxLength !== undefined && count >= maxLength * 0.8
  const describedBy = [ariaDescribedBy, showCounter ? `${textareaId}-count` : undefined]
    .filter(Boolean)
    .join(' ')

  return (
    <div
      className={cn(
        'w-full min-w-0 rounded-md border bg-background shadow-xs transition-[color,box-shadow]',
        'focus-within:border-ring focus-within:ring-[3px] focus-within:ring-ring/50',
        invalid && 'border-destructive focus-within:border-destructive',
        dragging && 'border-primary ring-[3px] ring-primary/30',
        className
      )}
      data-testid="markdown-editor"
      onDragOver={(e) => {
        if (!onUploadFile || !hasFiles(e)) return
        e.preventDefault()
        setDragging(true)
      }}
      onDragLeave={(e) => {
        if (e.currentTarget.contains(e.relatedTarget as Node | null)) return
        setDragging(false)
      }}
      onDrop={(e) => {
        if (!onUploadFile) return
        const files = filesFrom(e.dataTransfer?.files)
        setDragging(false)
        if (files.length === 0) return
        e.preventDefault()
        if (mode !== 'write') setMode('write')
        uploadFiles(files)
      }}
    >
      {!hideToolbar && (
        <div className="flex h-9 items-center gap-1 border-b px-1">
          <div
            role="tablist"
            aria-label={t('common.markdownEditor.mode', 'Editor mode')}
            className="flex shrink-0 items-center gap-0.5"
          >
            {(['write', 'preview'] as const).map((m) => (
              <button
                key={m}
                type="button"
                role="tab"
                aria-selected={mode === m}
                aria-controls={`${textareaId}-panel`}
                onClick={() => setMode(m)}
                className={cn(
                  'rounded px-2 py-1 text-xs font-medium transition-colors',
                  mode === m
                    ? 'bg-muted text-foreground'
                    : 'text-muted-foreground hover:text-foreground'
                )}
              >
                {m === 'write'
                  ? t('common.markdownEditor.write', 'Write')
                  : t('common.markdownEditor.preview', 'Preview')}
              </button>
            ))}
          </div>
          <div
            ref={toolbarRef}
            role="toolbar"
            aria-label={t('common.markdownEditor.toolbar', 'Formatting')}
            aria-controls={textareaId}
            className={cn(
              'flex min-w-0 flex-1 items-center justify-end gap-0.5 overflow-hidden',
              mode === 'preview' && 'invisible'
            )}
          >
            {visible.map((c) => (
              <ToolbarButton
                key={c.id}
                icon={c.icon}
                label={label(c)}
                shortcut={c.shortcut}
                onClick={() => runCommand(c.id)}
              />
            ))}
            {overflow.length > 0 && (
              <DropdownMenu modal={false}>
                <DropdownMenuTrigger asChild>
                  <button
                    type="button"
                    className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    aria-label={t('common.markdownEditor.more', 'More formatting')}
                    title={t('common.markdownEditor.more', 'More formatting')}
                  >
                    <Ellipsis className="h-4 w-4" />
                  </button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" onCloseAutoFocus={(e) => e.preventDefault()}>
                  {overflow.map((c) => {
                    const Icon = c.icon
                    return (
                      <DropdownMenuItem key={c.id} onSelect={() => runCommand(c.id)}>
                        <Icon className="me-2 h-4 w-4" />
                        {label(c)}
                      </DropdownMenuItem>
                    )
                  })}
                </DropdownMenuContent>
              </DropdownMenu>
            )}
          </div>
        </div>
      )}

      <div id={`${textareaId}-panel`} role={hideToolbar ? undefined : 'tabpanel'}>
        {mode === 'write' ? (
          <textarea
            ref={textareaRef}
            id={textareaId}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            onKeyDown={onKeyDown}
            onPaste={onPaste}
            placeholder={placeholder}
            aria-label={ariaLabel}
            aria-describedby={describedBy || undefined}
            aria-invalid={invalid || undefined}
            autoFocus={autoFocus}
            spellCheck
            style={{ minHeight: height }}
            className="block w-full resize-none bg-transparent px-3 py-2 text-base leading-relaxed outline-none sm:text-sm placeholder:text-muted-foreground"
          />
        ) : (
          <div className="overflow-y-auto px-3 py-2" style={{ minHeight: height, maxHeight }}>
            {value.trim() ? (
              <MarkdownPreview content={value} />
            ) : (
              <p className="text-sm text-muted-foreground">
                {t('common.markdownEditor.nothingToPreview', 'Nothing to preview yet.')}
              </p>
            )}
          </div>
        )}
      </div>

      {(uploads.length > 0 || showCounter) && (
        <div className="space-y-1 border-t px-3 py-1.5 text-xs text-muted-foreground">
          {uploads.map((u) => (
            <div key={u.key} className="flex items-center gap-2" role="status">
              <Loader2 className="h-3 w-3 shrink-0 animate-spin" aria-hidden />
              <span className="min-w-0 flex-1 truncate">
                {t('common.markdownEditor.uploading', 'Uploading {name}', { name: u.name })}
              </span>
              <span className="h-1 w-20 shrink-0 overflow-hidden rounded bg-muted">
                <span
                  className="block h-full bg-primary transition-[width]"
                  style={{ width: `${u.progress}%` }}
                />
              </span>
              <span className="w-8 shrink-0 text-end tabular-nums">{u.progress}%</span>
            </div>
          ))}
          {showCounter && (
            <p
              id={`${textareaId}-count`}
              className={cn('text-end tabular-nums', count > maxLength && 'text-destructive')}
            >
              {t('common.markdownEditor.counter', '{count} / {max} characters', {
                count,
                max: maxLength,
              })}
            </p>
          )}
        </div>
      )}

      {onUploadFile && (
        <input
          ref={fileInputRef}
          type="file"
          multiple
          className="hidden"
          tabIndex={-1}
          aria-hidden
          onChange={(e) => {
            uploadFiles(filesFrom(e.target.files))
            e.target.value = ''
          }}
        />
      )}
    </div>
  )
}

function ToolbarButton({
  icon: Icon,
  label,
  shortcut,
  onClick,
}: {
  icon: LucideIcon
  label: string
  shortcut?: string
  onClick: () => void
}) {
  const title = shortcut ? `${label} (Ctrl+${shortcut})` : label
  return (
    <button
      type="button"
      onClick={onClick}
      // Keep the textarea selection: a mouse down on the button would blur it.
      onMouseDown={(e) => e.preventDefault()}
      aria-label={label}
      title={title}
      className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      <Icon className="h-4 w-4" />
    </button>
  )
}

// Dynamic import OUTSIDE component to prevent re-creation on every render
const MDPreview = dynamic(
  () => import('@uiw/react-md-editor').then((mod) => mod.default.Markdown),
  { ssr: false }
)

interface MarkdownPreviewProps {
  content: string
  className?: string
}

export function MarkdownPreview({ content, className }: MarkdownPreviewProps) {
  const { resolvedTheme } = useTheme()

  return (
    <div
      className={cn('prose prose-sm dark:prose-invert max-w-none', className)}
      data-color-mode={resolvedTheme}
    >
      {/* Sanitised before and after rehype-attr. See @/lib/sanitize-markdown. */}
      <MDPreview source={content} {...markdownPreviewSecurityProps} />
    </div>
  )
}
