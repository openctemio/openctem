'use client'

import { useState } from 'react'
import { FlaskConical } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'

import type { ProxyPool } from '../types'
import { TestPoolDialog } from './test-pool-dialog'

/**
 * Test button of a pool. Starting a test needs sensors:egress:write (the
 * caller decides), and the pool needs at least one proxy. The dialog mounts
 * only while open, so nothing is fetched until someone asks.
 */
export function TestPoolButton({ pool, canWrite }: { pool: ProxyPool; canWrite: boolean }) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  if (!canWrite || pool.endpoints.length === 0) return null
  return (
    <>
      <Button type="button" variant="outline" size="sm" onClick={() => setOpen(true)}>
        <FlaskConical className="size-4" aria-hidden />
        {t('proxyPools.test.button', 'Test')}
      </Button>
      {open && <TestPoolDialog open={open} onOpenChange={setOpen} pool={pool} />}
    </>
  )
}
