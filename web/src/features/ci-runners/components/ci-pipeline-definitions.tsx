'use client'

/**
 * Pipeline definitions of a trust configuration (api RFC-051, rule
 * workflow_refs): "Only accept tokens from these pipeline files". The list
 * is built from project + file + branch, so nobody has to type the token's
 * format; a value copied from a refused job can be pasted as it is.
 *
 * What the token names (GitLab ci_config_ref_uri, GitHub job_workflow_ref) is
 * the pipeline's top-level configuration file, not the file a job is written
 * in: jobs pulled in with include: still name the top-level file.
 */

import { useState } from 'react'
import { Plus, X } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { useTranslation } from '@/context/i18n-provider'
import {
  defaultDefinitionFile,
  isPipelineDefinition,
  pipelineDefinition,
  type DefinitionCase,
} from '../lib/connect'
import type { CIProvider } from '../types'

/** The most entries the rule may hold (server: maxWorkflowRefs). */
export const MAX_DEFINITIONS = 20

export function CIPipelineDefinitions({
  provider,
  host,
  value,
  onChange,
  wholeGroup,
}: {
  provider: CIProvider
  /** The GitLab host the token names (from the configuration's address). */
  host: string
  value: string[]
  onChange: (next: string[]) => void
  /** The configuration admits whole groups or owners: every project must run a listed file. */
  wholeGroup: boolean
}) {
  const { t } = useTranslation()
  const isGitLab = provider === 'gitlab'
  const [kase, setKase] = useState<DefinitionCase>('central')
  const [project, setProject] = useState('')
  const [file, setFile] = useState(defaultDefinitionFile(provider, 'central'))
  const [branch, setBranch] = useState('main')
  const [pasted, setPasted] = useState('')
  const built = pipelineDefinition(provider, { host, project, file, branch })
  const full = value.length >= MAX_DEFINITIONS
  const add = (v: string) => {
    const x = v.trim()
    if (!x || value.includes(x) || full) return
    onChange([...value, x])
  }
  const pastedValid = !pasted.trim() || isPipelineDefinition(provider, pasted.trim())
  const cases: DefinitionCase[] = isGitLab ? ['central', 'own', 'custom'] : ['central', 'own']

  return (
    <div className="space-y-3" data-testid="ci-pipeline-definitions">
      <div className="space-y-1">
        <p className="text-sm font-medium" id="ci-defs-title">
          {t('scans.ci.defs.title', 'Only accept tokens from these pipeline files')}
        </p>
        <p className="text-xs text-muted-foreground">
          {isGitLab
            ? t(
                'scans.ci.defs.explainGitlab',
                'A job token names the top-level configuration file of its pipeline, not the file the job is written in. Jobs added with include: (local, project, template or component) still name the top-level file. A project whose CI/CD configuration file path was changed names that path. A configuration file kept in another project (file.yml@group/project) names that project and file: list that one file to accept only your central pipeline.'
              )
            : t(
                'scans.ci.defs.explainGithub',
                'A job token names the workflow file it runs. A job that calls a reusable workflow names that workflow: list your central workflow to accept only it.'
              )}
        </p>
        {wholeGroup && (
          <p className="text-xs text-warning" data-testid="ci-defs-whole-group">
            {t(
              'scans.ci.defs.wholeGroup',
              'Every project this configuration admits must run one of the files listed here, or its jobs are refused. The usual choice is one central file that every project includes as its configuration.'
            )}
          </p>
        )}
      </div>

      {value.length > 0 ? (
        <ul className="flex flex-col gap-1" aria-labelledby="ci-defs-title">
          {value.map((v) => (
            <li key={v} className="flex min-w-0 items-center gap-2">
              <Badge // label-ok: a pipeline definition is a file path, an identifier
                variant="outline"
                className="min-w-0 font-mono"
              >
                <span className="truncate" title={v}>
                  {v}
                </span>
              </Badge>
              <Button
                type="button"
                variant="ghost"
                size="icon-sm"
                aria-label={t('scans.ci.defs.remove', 'Remove {value}', { value: v })}
                onClick={() => onChange(value.filter((x) => x !== v))}
              >
                <X aria-hidden />
              </Button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-xs text-muted-foreground">
          {t('scans.ci.defs.none', 'Any pipeline file is accepted.')}
        </p>
      )}

      <fieldset className="space-y-3 rounded-md border p-3">
        <legend className="px-1 text-sm font-medium">
          {t('scans.ci.defs.add', 'Add a pipeline file')}
        </legend>
        <RadioGroup
          value={kase}
          onValueChange={(v) => {
            const c = v as DefinitionCase
            setKase(c)
            setFile(defaultDefinitionFile(provider, c))
          }}
        >
          {cases.map((c) => (
            <div key={c} className="flex items-start gap-2">
              <RadioGroupItem value={c} id={`ci-defs-case-${c}`} className="mt-0.5" />
              <Label htmlFor={`ci-defs-case-${c}`} className="font-normal">
                {t(`scans.ci.defs.case.${c}`, c)}
              </Label>
            </div>
          ))}
        </RadioGroup>
        <div className="grid gap-3 sm:grid-cols-3">
          <div className="space-y-1.5">
            <Label htmlFor="ci-defs-project">
              {kase === 'central'
                ? t('scans.ci.defs.centralProject', 'Project that holds the file')
                : t('scans.ci.defs.project', 'Project')}
            </Label>
            <Input
              id="ci-defs-project"
              value={project}
              placeholder={isGitLab ? 'my-group/ci' : 'acme/security'}
              onChange={(e) => setProject(e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ci-defs-file">{t('scans.ci.defs.file', 'File')}</Label>
            <Input
              id="ci-defs-file"
              value={file}
              placeholder={isGitLab ? 'scan.yml' : '.github/workflows/scan.yml'}
              onChange={(e) => setFile(e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="ci-defs-branch">{t('scans.ci.defs.branch', 'Branch')}</Label>
            <Input id="ci-defs-branch" value={branch} onChange={(e) => setBranch(e.target.value)} />
          </div>
        </div>
        {built && (
          <p className="break-all font-mono text-xs" data-testid="ci-defs-preview">
            {built}
          </p>
        )}
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={!built || full}
          onClick={() => {
            add(built)
            setProject('')
          }}
        >
          <Plus aria-hidden /> {t('scans.ci.defs.addBuilt', 'Add file')}
        </Button>
        <div className="space-y-1.5 border-t pt-3">
          <Label htmlFor="ci-defs-paste">
            {t('scans.ci.defs.paste', 'Or paste the value shown in a refusal')}
          </Label>
          <div className="flex gap-2">
            <Input
              id="ci-defs-paste"
              value={pasted}
              aria-invalid={!pastedValid || undefined}
              aria-describedby="ci-defs-paste-hint"
              placeholder={
                isGitLab
                  ? 'gitlab.example.com/my-group/my-project//.gitlab-ci.yml@refs/heads/main'
                  : 'acme/security/.github/workflows/scan.yml@refs/heads/main'
              }
              onChange={(e) => setPasted(e.target.value)}
            />
            <Button
              type="button"
              variant="outline"
              disabled={!pasted.trim() || !pastedValid || full}
              onClick={() => {
                add(pasted)
                setPasted('')
              }}
            >
              {t('scans.ci.defs.addPasted', 'Add value')}
            </Button>
          </div>
          <p id="ci-defs-paste-hint" className="text-xs text-muted-foreground">
            {pastedValid
              ? t(
                  'scans.ci.defs.pasteHint',
                  'For child pipelines and other cases, use the value shown in the refusal: it is exactly what the token says.'
                )
              : t('scans.ci.defs.pasteInvalid', 'This is not a pipeline file value (path@ref).')}
          </p>
        </div>
      </fieldset>
    </div>
  )
}
