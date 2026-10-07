'use client'

import { useMemo } from 'react'
import useSWR from 'swr'
import { get, post } from '@/lib/api/client'
import { pipelineEndpoints } from '@/lib/api/endpoints'
import type { PipelineStep } from '@/lib/api'
import {
  EMPTY_TABLE,
  toCapabilityTable,
  type CapabilityTable,
  type GraphValidation,
  type ScanStageList,
} from './capability-graph'

/**
 * The capability catalog, normalized for the builder. Static platform data:
 * fetched once per session.
 */
export function useCapabilityTable(): { table: CapabilityTable; isLoading: boolean } {
  const { data, isLoading } = useSWR<ScanStageList>(
    pipelineEndpoints.capabilities(),
    (url: string) => get<ScanStageList>(url),
    { revalidateOnFocus: false, revalidateOnReconnect: false, dedupingInterval: 10 * 60 * 1000 }
  )
  const table = useMemo(() => (data ? toCapabilityTable(data) : EMPTY_TABLE), [data])
  return { table, isLoading }
}

/** Checks draft steps with the API's graph validator (stores nothing). */
export function validatePipelineSteps(steps: PipelineStep[]): Promise<GraphValidation> {
  return post<GraphValidation>(pipelineEndpoints.verify(), {
    steps: steps.map((s, idx) => ({
      step_key: s.step_key,
      name: s.name,
      order: idx + 1,
      tool: s.tool,
      capabilities: s.capabilities,
      depends_on: s.depends_on ?? [],
      ...(s.config ? { config: s.config } : {}),
    })),
  })
}
