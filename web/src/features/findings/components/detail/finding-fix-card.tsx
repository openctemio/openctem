'use client'

/**
 * The Fix card: the one concrete action that closes the finding, by type
 * (lib/fix-guidance.ts). "Upgrade cross-spawn 7.0.3 → 7.0.5" with the npm
 * command, "Revoke and rotate the Stripe key", "Set encryption to AES256"…
 * Nothing renders when the finding has no concrete fix.
 */

import { ArrowRight, Check, Copy, Wrench } from 'lucide-react'
import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { copyToClipboard } from '@/lib/clipboard'
import { cn } from '@/lib/utils'
import type { FindingDetail } from '../../types'
import { fixGuidance, type FixCommand } from '../../lib/fix-guidance'

function CodeBlock({ cmd }: { cmd: FixCommand }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="min-w-0">
      <div className="mb-1 text-xs text-muted-foreground">{cmd.label}</div>
      <div className="relative">
        <pre className="overflow-x-auto rounded-md border bg-muted/60 py-2 ps-3 pe-10 font-mono text-xs leading-relaxed">
          {cmd.code}
        </pre>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="absolute end-1 top-1 size-7"
          aria-label={`Copy ${cmd.label} snippet`}
          onClick={async () => {
            if (await copyToClipboard(cmd.code)) {
              setCopied(true)
              setTimeout(() => setCopied(false), 1500)
            }
          }}
        >
          {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
        </Button>
      </div>
      {cmd.note && <p className="mt-1 text-xs text-muted-foreground">{cmd.note}</p>}
    </div>
  )
}

function Version({ children, tone }: { children: React.ReactNode; tone?: 'from' | 'to' }) {
  return (
    <code
      className={cn(
        'rounded px-1.5 py-0.5 font-mono text-sm',
        tone === 'to' ? 'bg-success/15 text-success' : 'bg-muted'
      )}
    >
      {children}
    </code>
  )
}

export interface FindingFixCardProps {
  finding: FindingDetail
  /** Opens the full remediation plan (the Remediation tab). */
  onOpenPlan?: () => void
  /** Drawer: no commands, just the action line. */
  compact?: boolean
  className?: string
}

export function FindingFixCard({ finding, onOpenPlan, compact, className }: FindingFixCardProps) {
  const g = fixGuidance(finding)
  if (!g) return null

  let body: React.ReactNode
  switch (g.kind) {
    case 'upgrade': {
      const how = [
        g.dependencyType === 'direct'
          ? 'Direct dependency'
          : g.dependencyType === 'transitive'
            ? 'Transitive dependency'
            : null,
        g.manifestFile ? `in ${g.manifestFile}` : null,
        g.ecosystem || null,
      ].filter(Boolean)
      body = (
        <>
          <p className="flex flex-wrap items-center gap-x-1.5 gap-y-1 text-base font-medium">
            Upgrade <span className="font-semibold">{g.packageName}</span>
            <Version tone="from">{g.from}</Version>
            <ArrowRight className="h-4 w-4 text-muted-foreground" aria-label="to" />
            <Version tone="to">{g.to}</Version>
          </p>
          {how.length > 0 && (
            <p className="mt-1 text-sm text-muted-foreground">{how.join(' · ')}</p>
          )}
          {!compact && g.commands.length > 0 && (
            <div className="mt-3 grid gap-2">
              {g.commands.map((c) => (
                <CodeBlock key={c.label} cmd={c} />
              ))}
            </div>
          )}
          {g.otherFixedVersions.length > 0 && (
            <p className="mt-2 text-xs text-muted-foreground">
              Also fixed in{' '}
              {g.otherFixedVersions.map((v, i) => (
                <span key={v}>
                  {i > 0 && ', '}
                  <code className="font-mono">{v}</code>
                </span>
              ))}{' '}
              (other release lines).
            </p>
          )}
        </>
      )
      break
    }
    case 'no-fix':
      body = (
        <>
          <p className="text-base font-medium">
            No fixed version of <span className="font-semibold">{g.packageName}</span> yet
          </p>
          <p className="mt-1 text-sm text-muted-foreground">
            {g.from} is affected and the advisory lists no patched release. Replace the package,
            remove the vulnerable code path, or accept the risk with a compensating control.
          </p>
        </>
      )
      break
    case 'rotate-secret':
      body = (
        <>
          <p className="text-base font-medium">
            Revoke and rotate {g.service ? `the ${g.service} credential` : 'the credential'}
          </p>
          {!compact && (
            <ol className="mt-2 list-decimal space-y-1 ps-5 text-sm text-muted-foreground">
              {g.steps.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ol>
          )}
        </>
      )
      break
    case 'misconfig':
      body = (
        <>
          <p className="text-base font-medium">
            {g.resource ? (
              <>
                Reconfigure <span className="font-mono text-sm">{g.resource}</span>
              </>
            ) : (
              'Reconfigure the resource'
            )}
          </p>
          {g.policy && <p className="mt-1 text-sm text-muted-foreground">Policy: {g.policy}</p>}
          {!compact && (g.expected || g.actual) && (
            <dl className="mt-3 grid gap-2 sm:grid-cols-2">
              <div className="min-w-0 rounded-md border border-success/30 bg-success/5 p-2.5">
                <dt className="text-xs font-medium text-success">Expected</dt>
                <dd className="mt-1 font-mono text-xs break-words whitespace-pre-wrap">
                  {g.expected || 'Not configured'}
                </dd>
              </div>
              <div className="min-w-0 rounded-md border border-destructive/30 bg-destructive/5 p-2.5">
                <dt className="text-xs font-medium text-destructive">Actual</dt>
                <dd className="mt-1 font-mono text-xs break-words whitespace-pre-wrap">
                  {g.actual || 'Not configured'}
                </dd>
              </div>
            </dl>
          )}
        </>
      )
      break
    case 'text':
      body = (
        <>
          {g.text && (
            <p
              className={cn(
                'text-sm leading-relaxed whitespace-pre-wrap',
                compact && 'line-clamp-3'
              )}
            >
              {g.text}
            </p>
          )}
          {!compact && g.fixCode && (
            <div className="mt-3">
              <CodeBlock cmd={{ label: 'Suggested fix', code: g.fixCode }} />
            </div>
          )}
        </>
      )
      break
  }

  return (
    <section
      aria-label="Fix"
      data-slot="finding-fix"
      data-kind={g.kind}
      className={cn('rounded-lg border bg-card p-4', className)}
    >
      <div className="mb-2 flex items-center justify-between gap-2">
        <h2 className="flex items-center gap-1.5 text-sm font-semibold">
          <Wrench className="h-4 w-4" aria-hidden />
          Fix
        </h2>
        {onOpenPlan && (
          <Button variant="link" size="sm" className="h-auto p-0 text-xs" onClick={onOpenPlan}>
            Remediation plan
          </Button>
        )}
      </div>
      {body}
    </section>
  )
}
