'use client'

/**
 * The targets field of a scan form: the selection as chips inside one field,
 * and an input at its end to type or paste more. Enter, comma, space or Tab
 * adds what is typed; a paste of many lines or a comma list adds them all;
 * Backspace on an empty input removes the last typed target. A typed chip
 * (one with onEdit) is edited in place: click, Enter or F2 turns it into an
 * input; Enter or blur commits, Escape cancels, an empty commit removes it.
 * Each chip's remove button has a 44 px tap area. Format only: whether a target may be
 * scanned is the server's scope check.
 */

import { useRef, useState, type ClipboardEvent, type KeyboardEvent } from 'react'
import { FolderOpen, X } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

export interface TargetChip {
  key: string
  label: string
  kind: 'asset' | 'typed' | 'group' | 'expanded' | 'invalid'
  /** Why an invalid entry is invalid (shown as its title). */
  title?: string
  onRemove?: () => void
  /**
   * Replace this typed target with what was edited ('' removes it). Set only
   * for typed text; asset and group chips are references and stay as they are.
   */
  onEdit?: (next: string) => void
  /** The text to edit when it differs from the label. */
  editValue?: string
}

/** Chips shown before "Show all". */
export const VISIBLE_CHIPS = 60

/** The targets in a typed or pasted text: split on whitespace, commas and semicolons. */
export function splitTargetInput(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter(Boolean)
}

interface TargetChipsFieldProps {
  id: string
  chips: TargetChip[]
  /** Add these typed or pasted targets. */
  onAdd: (targets: string[]) => void
  /** Remove the last typed target (Backspace on an empty input). */
  onRemoveLast?: () => void
  invalid?: boolean
  describedBy?: string
  labelledBy?: string
}

export function TargetChipsField({
  id,
  chips,
  onAdd,
  onRemoveLast,
  invalid,
  describedBy,
  labelledBy,
}: TargetChipsFieldProps) {
  const { t } = useTranslation()
  const [text, setText] = useState('')
  const [all, setAll] = useState(false)
  const [editing, setEditing] = useState<{ key: string; text: string } | null>(null)
  // Enter commits and unmounts the input, whose blur would commit again.
  const finished = useRef(false)

  const startEdit = (chip: TargetChip) => {
    finished.current = false
    setEditing({ key: chip.key, text: chip.editValue ?? chip.label })
  }
  const finishEdit = (chip: TargetChip, save: boolean, refocus: boolean) => {
    if (finished.current) return
    finished.current = true
    const next = editing?.text.trim() ?? ''
    setEditing(null)
    if (save && next !== (chip.editValue ?? chip.label)) chip.onEdit?.(next)
    if (refocus) document.getElementById(id)?.focus()
  }

  const commit = (value: string) => {
    const tokens = splitTargetInput(value)
    if (tokens.length > 0) onAdd(tokens)
    setText('')
  }

  const onChange = (value: string) => {
    // A separator typed (or a filled-in list): add every finished target,
    // keep the one still being typed.
    if (/[\s,;]/.test(value)) {
      const trailing = /[\s,;]$/.test(value)
      const tokens = splitTargetInput(value)
      const done = trailing ? tokens : tokens.slice(0, -1)
      if (done.length > 0) onAdd(done)
      setText(trailing ? '' : (tokens.at(-1) ?? ''))
      return
    }
    setText(value)
  }

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' || (e.key === 'Tab' && text.trim() !== '')) {
      if (text.trim() === '') return
      e.preventDefault()
      commit(text)
    } else if (e.key === 'Backspace' && text === '' && onRemoveLast) {
      onRemoveLast()
    }
  }

  const onPaste = (e: ClipboardEvent<HTMLInputElement>) => {
    const pasted = e.clipboardData.getData('text')
    if (!/[\s,;]/.test(pasted.trim())) return
    e.preventDefault()
    commit(`${text} ${pasted}`)
  }

  const shown = all ? chips : chips.slice(0, VISIBLE_CHIPS)
  const hidden = chips.length - shown.length

  return (
    <div
      className={cn(
        'flex max-h-60 min-h-11 min-w-0 cursor-text flex-wrap items-center gap-1.5 overflow-y-auto rounded-md border border-input bg-background px-2 py-1.5 focus-within:ring-2 focus-within:ring-ring',
        invalid && 'border-destructive'
      )}
      onClick={(e) => {
        if (e.target === e.currentTarget) document.getElementById(id)?.focus()
      }}
      data-testid="target-chips-field"
    >
      <ul className="contents" aria-label={t('scans.targetsStep.selection')}>
        {shown.map((chip) => (
          <li
            key={chip.key}
            title={chip.title ?? chip.label}
            className={cn(
              'flex h-8 max-w-full min-w-0 items-center gap-1 rounded-full border ps-2.5 text-xs',
              !chip.onRemove && 'pe-2.5',
              chip.kind === 'expanded' && 'border-dashed text-muted-foreground',
              chip.kind === 'invalid' && 'border-destructive text-destructive'
            )}
            data-kind={chip.kind}
          >
            {chip.kind === 'group' && <FolderOpen className="h-3 w-3 shrink-0" aria-hidden />}
            {editing?.key === chip.key ? (
              <input
                autoFocus
                value={editing.text}
                onChange={(e) => setEditing({ key: chip.key, text: e.target.value })}
                onFocus={(e) => e.currentTarget.select()}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault()
                    finishEdit(chip, true, true)
                  } else if (e.key === 'Escape') {
                    e.preventDefault()
                    e.stopPropagation()
                    finishEdit(chip, false, true)
                  }
                }}
                onBlur={() => finishEdit(chip, true, false)}
                aria-label={t('scans.targetsStep.editTarget', undefined, { name: chip.label })}
                autoComplete="off"
                autoCapitalize="none"
                spellCheck={false}
                size={Math.max(editing.text.length, 8)}
                className="h-6 min-w-0 max-w-full bg-transparent font-mono text-xs outline-hidden"
                data-testid="target-chip-edit"
              />
            ) : chip.onEdit ? (
              <button
                type="button"
                onClick={() => startEdit(chip)}
                onKeyDown={(e) => {
                  if (e.key === 'F2') {
                    e.preventDefault()
                    startEdit(chip)
                  }
                }}
                aria-label={t('scans.targetsStep.editTarget', undefined, { name: chip.label })}
                aria-keyshortcuts="F2"
                className="min-w-0 truncate rounded font-mono hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-hidden"
              >
                {chip.label}
              </button>
            ) : (
              <span className="min-w-0 truncate font-mono">{chip.label}</span>
            )}
            {chip.onRemove && (
              <button
                type="button"
                onClick={chip.onRemove}
                className="relative flex h-8 w-8 shrink-0 items-center justify-center rounded-full after:absolute after:-inset-1.5 after:content-[''] hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-hidden"
                aria-label={t('scans.summary.remove', undefined, { name: chip.label })}
              >
                <X className="h-3.5 w-3.5" aria-hidden />
              </button>
            )}
          </li>
        ))}
      </ul>
      {hidden > 0 && (
        <button
          type="button"
          className="h-8 rounded-full px-2 text-xs text-signal-text hover:underline"
          onClick={() => setAll(true)}
        >
          {t('scans.targetsStep.showAllChips', undefined, { count: hidden })}
        </button>
      )}
      <input
        id={id}
        value={text}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={onKeyDown}
        onPaste={onPaste}
        onBlur={() => commit(text)}
        placeholder={
          chips.length === 0
            ? t('scans.targetsStep.placeholder')
            : t('scans.targetsStep.placeholderMore')
        }
        aria-labelledby={labelledBy}
        aria-describedby={describedBy}
        aria-invalid={invalid || undefined}
        autoComplete="off"
        autoCapitalize="none"
        spellCheck={false}
        enterKeyHint="enter"
        className="h-8 min-w-[10rem] flex-1 bg-transparent font-mono text-sm outline-hidden placeholder:font-sans placeholder:text-muted-foreground"
      />
    </div>
  )
}
