'use client'

/**
 * Paste source of scan targets, shared by Quick scan and the New Scan "Paste
 * a list" panel: a list typed, pasted (one per line, or separated by commas,
 * semicolons or spaces; `#` comments skipped) or read from a `.txt` / `.csv`
 * file in the browser. Under it, the analysis as you type: how many targets
 * of each kind, repeats folded, and every entry that will not be added with
 * its reason, to edit or remove one by one or all at once. "Clean up"
 * rewrites the list normalized. Whether a target may be scanned is the scope
 * check's answer, never decided here. Design: research/418.
 */

import { useId, useMemo, useRef, useState, type ChangeEvent } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { AlertCircle, Pencil, Sparkles, Upload, X } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { VirtualList } from '@/components/ui/virtual-list'
import { cn } from '@/lib/utils'
import { TargetLinesInput } from '../new-scan/target-lines-input'
import {
  isRefusedKind,
  parsePastedTargets,
  withoutTargets,
  replaceEntryInLines,
  TARGET_KIND_LABELS,
  targetFileLines,
  targetKey,
  type ClassifiedTarget,
  type TargetKind,
} from '../../lib/target-format'

const EXAMPLES = ['example.com', '*.example.com', '203.0.113.0/24', 'https://app.example.com']

/** Largest file read (bytes) and most entries taken from one file. */
export const MAX_TARGET_FILE_BYTES = 1024 * 1024
export const MAX_TARGET_FILE_ENTRIES = 10_000

const ROW = 52

/** A file's text, read in the browser (never uploaded anywhere). */
function readText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(typeof reader.result === 'string' ? reader.result : '')
    reader.onerror = () => reject(reader.error)
    reader.readAsText(file)
  })
}

interface PasteSourceProps {
  value: string[]
  onChange: (targets: string[]) => void
  /** Rendered under the input (the wildcard suggestions). */
  children?: React.ReactNode
  /** The textarea's id (one per page). */
  id?: string
  rows?: number
}

function InvalidRow({
  entry,
  onRemove,
  onReplace,
}: {
  entry: ClassifiedTarget
  onRemove: () => void
  onReplace: (next: string) => void
}) {
  const { t } = useTranslation()
  const [editing, setEditing] = useState(false)
  const [text, setText] = useState(entry.input)
  const reason = entry.reasonKey ? t(entry.reasonKey, entry.reason) : entry.reason
  if (editing) {
    return (
      <form
        className="flex h-full items-center gap-1.5 px-1"
        onSubmit={(e) => {
          e.preventDefault()
          setEditing(false)
          if (text.trim() && text.trim() !== entry.input) onReplace(text.trim())
        }}
      >
        <Input
          autoFocus
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') {
              e.stopPropagation()
              setEditing(false)
            }
          }}
          aria-label={t('scans.paste.edit', undefined, { name: entry.input })}
          className="h-9 min-w-0 flex-1 font-mono text-sm"
          autoCapitalize="none"
          spellCheck={false}
        />
        <Button type="submit" size="sm" className="h-9">
          {t('scans.paste.save')}
        </Button>
      </form>
    )
  }
  return (
    <div className="flex h-full min-w-0 items-center gap-2 border-b px-1 last:border-b-0">
      <AlertCircle className="h-4 w-4 shrink-0 text-destructive" aria-hidden />
      <span className="min-w-0 flex-1">
        <span className="block truncate font-mono text-sm" title={entry.input}>
          {entry.input}
        </span>
        <span className="block truncate text-xs text-muted-foreground" title={reason}>
          {reason}
        </span>
      </span>
      <Button
        type="button"
        variant="ghost"
        size="icon"
        className="h-9 w-9 shrink-0 max-sm:h-11 max-sm:w-11"
        onClick={() => setEditing(true)}
        aria-label={t('scans.paste.edit', undefined, { name: entry.input })}
      >
        <Pencil className="h-4 w-4" aria-hidden />
      </Button>
      <Button
        type="button"
        variant="ghost"
        size="icon"
        className="h-9 w-9 shrink-0 max-sm:h-11 max-sm:w-11"
        onClick={onRemove}
        aria-label={t('scans.paste.removeEntry', undefined, { name: entry.input })}
      >
        <X className="h-4 w-4" aria-hidden />
      </Button>
    </div>
  )
}

export function PasteSource({
  value,
  onChange,
  children,
  id = 'custom-targets',
  rows = 6,
}: PasteSourceProps) {
  const { t } = useTranslation()
  const fileRef = useRef<HTMLInputElement>(null)
  const statusId = `${id}-status`
  const fileHintId = useId()
  const [fileNote, setFileNote] = useState<{ tone: 'muted' | 'error'; text: string } | null>(null)
  const parsed = useMemo(() => parsePastedTargets(value), [value])
  const kinds = (Object.entries(parsed.byKind) as [TargetKind, number][]).filter(
    ([k]) => !isRefusedKind(k)
  )
  const canClean =
    parsed.duplicates > 0 || parsed.lines.some((l) => !isRefusedKind(l.kind) && l.value !== l.input)

  const readFile = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    if (!/\.(txt|csv)$/i.test(file.name)) {
      setFileNote({ tone: 'error', text: t('scans.paste.fileType') })
      return
    }
    if (file.size > MAX_TARGET_FILE_BYTES) {
      setFileNote({
        tone: 'error',
        text: t('scans.paste.fileTooLarge', undefined, { name: file.name }),
      })
      return
    }
    let text: string
    try {
      text = await readText(file)
    } catch {
      setFileNote({
        tone: 'error',
        text: t('scans.paste.fileUnreadable', undefined, { name: file.name }),
      })
      return
    }
    const entries = targetFileLines(text, file.name)
    if (entries.length > MAX_TARGET_FILE_ENTRIES) {
      setFileNote({
        tone: 'error',
        text: t('scans.paste.fileTooMany', undefined, {
          name: file.name,
          max: MAX_TARGET_FILE_ENTRIES.toLocaleString(),
        }),
      })
      return
    }
    setFileNote({
      tone: 'muted',
      text: t('scans.paste.fileRead', undefined, { count: entries.length, name: file.name }),
    })
    onChange([...value, ...entries])
  }

  return (
    <div className="min-w-0 space-y-3">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div className="min-w-0">
          <Label htmlFor={id} className="text-sm">
            {t('scans.paste.label')}
          </Label>
          <p className="text-muted-foreground text-xs">{t('scans.paste.format')}</p>
        </div>
        <div className="flex flex-wrap items-center gap-1">
          {canClean && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="h-9 px-2 text-xs max-sm:min-h-11"
              onClick={() => onChange([...parsed.targets, ...parsed.invalid.map((i) => i.input)])}
            >
              <Sparkles className="me-1 h-3 w-3" aria-hidden />
              {t('scans.paste.cleanUp')}
            </Button>
          )}
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-9 max-sm:min-h-11"
            onClick={() => fileRef.current?.click()}
            aria-describedby={fileHintId}
          >
            <Upload className="me-1.5 h-4 w-4" aria-hidden />
            {t('scans.paste.upload')}
          </Button>
          <input
            ref={fileRef}
            type="file"
            accept=".txt,.csv,text/plain,text/csv"
            className="sr-only"
            tabIndex={-1}
            aria-hidden
            onChange={(e) => void readFile(e)}
            data-testid="target-file-input"
          />
        </div>
      </div>
      <p id={fileHintId} className="sr-only">
        {t('scans.paste.uploadHint')}
      </p>
      <TargetLinesInput
        id={id}
        rows={rows}
        placeholder={'example.com\n*.example.com\n203.0.113.0/24\nhttps://api.example.com/v1'}
        value={value}
        onChange={onChange}
        aria-invalid={parsed.invalid.length > 0 || undefined}
        aria-describedby={statusId}
        className={cn('font-mono text-sm', parsed.invalid.length > 0 && 'border-destructive')}
      />
      {fileNote && (
        <p
          role={fileNote.tone === 'error' ? 'alert' : 'status'}
          className={cn(
            'text-xs',
            fileNote.tone === 'error' ? 'text-destructive' : 'text-muted-foreground'
          )}
        >
          {fileNote.text}
        </p>
      )}

      <div id={statusId} aria-live="polite" className="min-w-0 space-y-2">
        {parsed.lines.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5 text-xs" data-testid="paste-counts">
            <span className="text-muted-foreground">
              {t(
                parsed.targets.length === 1 ? 'scans.paste.targetsOne' : 'scans.paste.targetsMany',
                undefined,
                { count: parsed.targets.length }
              )}
            </span>
            {kinds.map(([kind, n]) => (
              <Badge key={kind} variant="secondary" className="text-[11px]">
                {n} {t(`scans.kind.${kind}`, TARGET_KIND_LABELS[kind])}
              </Badge>
            ))}
            {parsed.duplicates > 0 && (
              <span className="text-muted-foreground">
                {t(
                  parsed.duplicates === 1 ? 'scans.paste.repeatedOne' : 'scans.paste.repeatedMany',
                  undefined,
                  { count: parsed.duplicates }
                )}
              </span>
            )}
          </div>
        )}
      </div>
      {parsed.invalid.length > 0 && (
        <div className="min-w-0 space-y-1">
          <div className="flex items-center justify-between gap-2">
            <p className="text-xs font-medium text-destructive">
              {t('scans.paste.notAdded', undefined, { count: parsed.invalid.length })}
            </p>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="h-8 px-2 text-xs max-sm:min-h-11"
              onClick={() =>
                onChange(
                  withoutTargets(
                    value,
                    parsed.invalid.map((i) => targetKey(i.input))
                  )
                )
              }
            >
              {t('scans.paste.removeAllInvalid')}
            </Button>
          </div>
          <VirtualList
            items={parsed.invalid}
            rowHeight={ROW}
            maxHeight={ROW * 5}
            label={t('scans.paste.invalidLines')}
            getKey={(entry, i) => `${i}:${entry.input}`}
            className="border"
            data-testid="paste-invalid-list"
            renderRow={(entry) => (
              <InvalidRow
                entry={entry}
                onRemove={() => onChange(withoutTargets(value, [targetKey(entry.input)]))}
                onReplace={(next) => onChange(replaceEntryInLines(value, entry.input, next))}
              />
            )}
          />
        </div>
      )}

      {children}

      {value.length === 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-muted-foreground text-xs">{t('scans.paste.examples')}</span>
          {EXAMPLES.map((example) => (
            <button
              key={example}
              type="button"
              onClick={() => onChange([...value, example])}
              className="min-h-8 rounded bg-muted px-2 font-mono text-xs text-muted-foreground transition-colors hover:bg-muted/80 hover:text-foreground"
            >
              {example}
            </button>
          ))}
        </div>
      )}
      <p className="text-muted-foreground text-xs">
        {t('scans.paste.wildcardHelp', undefined, { pattern: '*.example.com' })}
      </p>
    </div>
  )
}
