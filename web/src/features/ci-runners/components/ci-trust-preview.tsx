'use client'

/**
 * Check a sample token against a draft trust configuration (api RFC-051
 * section 3.1): the API verifies its signature against the issuer's keys and
 * says what it reads and whether the rules admit it. The sample stays in this
 * component's state only; the API stores nothing and records no token id.
 */

import { useState } from 'react'
import { CheckCircle2, ShieldX } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { getErrorMessage } from '@/lib/api/error-handler'
import { usePreviewTrustConfig } from '../api/use-ci'
import type { CIProvider, CITrustConfigRequest, CITrustPreview } from '../types'

const NORMALIZED_LABELS: [string, string][] = [
  ['repository', 'Repository'],
  ['repository_id', 'Repository id'],
  ['owner', 'Owner'],
  ['ref', 'Ref'],
  ['branch', 'Branch'],
  ['pull_request', 'Pull request'],
  ['commit_sha', 'Commit'],
  ['event', 'Event'],
  ['environment', 'Environment'],
  ['organization', 'Organization'],
  ['run_id', 'Run'],
  ['job_id', 'Job'],
]

export function CITrustPreview({
  provider,
  draft,
}: {
  provider: CIProvider
  draft: () => CITrustConfigRequest
}) {
  const { trigger, isMutating } = usePreviewTrustConfig()
  const [token, setToken] = useState('')
  const [commit, setCommit] = useState('')
  const [repository, setRepository] = useState('')
  const [result, setResult] = useState<CITrustPreview | null>(null)
  const [error, setError] = useState('')
  const asksCommit = provider === 'circleci' || provider === 'jenkins' || provider === 'bitbucket'

  const check = async () => {
    setError('')
    setResult(null)
    try {
      setResult(
        await trigger({
          config: draft(),
          id_token: token.trim(),
          commit_sha: commit.trim() || undefined,
          repository: repository.trim() || undefined,
        })
      )
    } catch (e) {
      setError(getErrorMessage(e))
    }
  }

  const normalized = (result?.normalized ?? {}) as Record<string, unknown>
  return (
    <div className="space-y-2 rounded-md border p-3" data-testid="ci-trust-preview">
      <Label htmlFor="ci-sample">Check a sample token</Label>
      <p className="text-xs text-muted-foreground">
        Paste a token from a job of this pipeline. It is verified against the issuer&apos;s keys and
        never stored; it can still be used by its job.
      </p>
      <Textarea
        id="ci-sample"
        rows={3}
        className="font-mono text-xs"
        placeholder="eyJ..."
        value={token}
        onChange={(e) => setToken(e.target.value)}
        autoComplete="off"
        spellCheck={false}
      />
      {asksCommit && (
        <Input
          aria-label="Commit the job reports"
          placeholder="Commit the job reports (only where the token signs none)"
          value={commit}
          onChange={(e) => setCommit(e.target.value)}
        />
      )}
      {provider === 'bitbucket' && (
        <Input
          aria-label="Repository the job reports"
          placeholder="workspace/repository"
          value={repository}
          onChange={(e) => setRepository(e.target.value)}
        />
      )}
      <Button
        type="button"
        variant="outline"
        size="sm"
        disabled={!token.trim() || isMutating}
        onClick={check}
      >
        Check token
      </Button>
      {error && <p className="text-sm text-destructive">{error}</p>}
      {result && (
        <div className="space-y-2 text-sm" data-testid="ci-trust-preview-result">
          <div className="flex flex-wrap gap-2">
            {result.verified ? (
              <Badge variant="outline">
                <CheckCircle2 className="size-3" aria-hidden /> Signature verified
              </Badge>
            ) : (
              <Badge variant="destructive">
                <ShieldX className="size-3" aria-hidden /> Not verified
              </Badge>
            )}
            {result.expired && <Badge variant="secondary">Expired</Badge>}
            {result.verified &&
              (result.admitted ? (
                <Badge>Admitted</Badge>
              ) : (
                <Badge variant="destructive">Refused: {result.refusal?.code}</Badge>
              ))}
            {result.normalized && !result.normalized.commit_verified && (
              <Badge variant="secondary">Commit reported by the job</Badge>
            )}
          </div>
          {result.verify_error && (
            <p className="break-all text-muted-foreground">{result.verify_error}</p>
          )}
          {result.refusal?.detail && (
            <p className="break-all text-muted-foreground">{result.refusal.detail}</p>
          )}
          {result.normalized && (
            <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
              {NORMALIZED_LABELS.filter(([k]) => normalized[k]).map(([k, label]) => (
                <div key={k} className="contents">
                  <dt className="text-muted-foreground">{label}</dt>
                  <dd className="break-all">{String(normalized[k])}</dd>
                </div>
              ))}
              {result.repository_asset && (
                <div className="contents">
                  <dt className="text-muted-foreground">Repository asset</dt>
                  <dd className="break-all">{result.repository_asset}</dd>
                </div>
              )}
            </dl>
          )}
          <details>
            <summary className="cursor-pointer text-muted-foreground">Claims</summary>
            <pre className="max-h-60 overflow-auto rounded bg-muted p-2 text-xs">
              {JSON.stringify(result.claims ?? {}, null, 2)}
            </pre>
          </details>
        </div>
      )}
    </div>
  )
}
