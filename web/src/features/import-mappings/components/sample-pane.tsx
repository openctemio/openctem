'use client'

import { toast } from 'sonner'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTranslation } from '@/context/i18n-provider'
import { withSource, type MappingDraft } from '../lib/mapping-model'
import { MAX_SAMPLE_BYTES } from '../lib/targets'
import {
  MAPPING_SOURCES,
  type CsvDelimiter,
  type MappingSource,
} from '../types/import-mapping.types'

const DELIMITERS: { value: CsvDelimiter; key: string; label: string }[] = [
  { value: 'auto', key: 'auto', label: 'Detect' },
  { value: ',', key: 'comma', label: 'Comma' },
  { value: ';', key: 'semicolon', label: 'Semicolon' },
  { value: '\t', key: 'tab', label: 'Tab' },
  { value: '|', key: 'pipe', label: 'Pipe' },
]

/** The source type a file name suggests, if any. */
export function sourceFromFileName(name: string): MappingSource | undefined {
  const ext = name.toLowerCase().split('.').pop() ?? ''
  if (ext === 'csv' || ext === 'tsv') return 'csv'
  if (ext === 'json') return 'json'
  if (ext === 'jsonl' || ext === 'ndjson') return 'jsonl'
  if (ext === 'xml') return 'xml'
  return undefined
}

interface SamplePaneProps {
  draft: MappingDraft
  onChange: (draft: MappingDraft) => void
  file: File | null
  onFile: (file: File | null) => void
  /** Set the source type from the file name (a mapping not saved yet). */
  autoSource: boolean
  readOnly: boolean
}

/** The sample file and how the input is read. */
export function SamplePane({
  draft,
  onChange,
  file,
  onFile,
  autoSource,
  readOnly,
}: SamplePaneProps) {
  const { t } = useTranslation()
  const delimiter = draft.csv?.delimiter ?? 'auto'

  return (
    <div className="grid gap-4">
      <div className="grid gap-1.5">
        <Label htmlFor="im-sample">{t('importMappings.sample.file', 'Sample file')}</Label>
        <Input
          id="im-sample"
          type="file"
          accept=".csv,.tsv,.json,.jsonl,.ndjson,.xml,.txt,text/csv,application/json,application/xml,text/xml"
          disabled={readOnly}
          onChange={(e) => {
            const f = e.target.files?.[0] ?? null
            if (f && f.size > MAX_SAMPLE_BYTES) {
              toast.error(t('importMappings.sample.tooLarge', 'The sample is larger than 5 MiB'))
              e.target.value = ''
              return
            }
            onFile(f)
            const guess = f ? sourceFromFileName(f.name) : undefined
            if (autoSource && guess && guess !== draft.source) onChange(withSource(draft, guess))
          }}
        />
        <p className="text-xs text-muted-foreground">
          {file
            ? t(
                'importMappings.sample.chosen',
                '{name}, {size} KiB. Only used for the preview; nothing is stored.',
                {
                  name: file.name,
                  size: Math.max(1, Math.round(file.size / 1024)),
                }
              )
            : t(
                'importMappings.sample.help',
                'Up to 5 MiB. The preview reads it with the mapping; nothing is stored.'
              )}
        </p>
      </div>

      <div className="grid gap-1.5">
        <Label htmlFor="im-source">{t('importMappings.sample.source', 'Input type')}</Label>
        <Select
          value={draft.source}
          disabled={readOnly}
          onValueChange={(v) => onChange(withSource(draft, v as MappingSource))}
        >
          <SelectTrigger id="im-source" className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {MAPPING_SOURCES.map((s) => (
              <SelectItem key={s} value={s}>
                {t(`importMappings.source.${s}`, s.toUpperCase())}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {draft.source === 'csv' && (
        <div className="grid gap-4">
          <div className="grid gap-1.5">
            <Label htmlFor="im-delim">{t('importMappings.sample.delimiter', 'Delimiter')}</Label>
            <Select
              value={delimiter}
              disabled={readOnly}
              onValueChange={(v) =>
                onChange({ ...draft, csv: { ...draft.csv, delimiter: v as CsvDelimiter } })
              }
            >
              <SelectTrigger id="im-delim" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {DELIMITERS.map((d) => (
                  <SelectItem key={d.key} value={d.value}>
                    {t(`importMappings.delimiter.${d.key}`, d.label)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="im-skip">
              {t('importMappings.sample.skipRows', 'Lines before the header')}
            </Label>
            <Input
              id="im-skip"
              type="number"
              inputMode="numeric"
              min={0}
              max={100}
              disabled={readOnly}
              value={draft.csv?.skip_rows ?? 0}
              onChange={(e) => {
                const n = Number.parseInt(e.target.value, 10)
                const skip = Number.isFinite(n) ? Math.min(100, Math.max(0, n)) : 0
                onChange({ ...draft, csv: { ...draft.csv, skip_rows: skip } })
              }}
            />
          </div>
        </div>
      )}

      {(draft.source === 'json' || draft.source === 'xml') && (
        <div className="grid gap-1.5">
          <Label htmlFor="im-each">
            {draft.source === 'xml'
              ? t('importMappings.sample.eachXml', 'Record elements')
              : t('importMappings.sample.eachJson', 'Path of the record list')}
          </Label>
          <Input
            id="im-each"
            className="font-mono text-xs"
            value={draft.each ?? ''}
            disabled={readOnly}
            placeholder={draft.source === 'xml' ? '//testcase' : '/findings'}
            onChange={(e) => onChange({ ...draft, each: e.target.value || undefined })}
          />
          <p className="text-xs text-muted-foreground">
            {draft.source === 'xml'
              ? t(
                  'importMappings.sample.eachXmlHelp',
                  'Required. An absolute element path such as /testsuites/testsuite/testcase, or //name for that element at any depth.'
                )
              : t(
                  'importMappings.sample.eachJsonHelp',
                  'Leave empty when the document is the list itself, or one record.'
                )}
          </p>
        </div>
      )}
    </div>
  )
}
