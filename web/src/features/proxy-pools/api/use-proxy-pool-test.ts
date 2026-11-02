/**
 * The Test button of a proxy pool: the platform asks up to three online
 * sensors to test every endpoint (it never connects to a proxy itself) and
 * the dialog polls for their results.
 */

'use client'

import useSWR from 'swr'

import { get, post } from '@/lib/api/client'
import { proxyPoolEndpoints } from '@/lib/api/endpoints'

import { allFinished } from '../lib/proxy-test'
import type { ProxyTestResultsResponse, ProxyTestStartResponse } from '../types'

/** How often the results are polled while a test is running. */
export const TEST_POLL_MS = 2000

export function startProxyPoolTest(poolId: string, sensorIds: string[]) {
  return post<ProxyTestStartResponse>(proxyPoolEndpoints.test(poolId), { sensor_ids: sensorIds })
}

/**
 * The next poll: none once every test ended. Module scope so its identity is
 * stable; SWR restarts its timer when `refreshInterval` changes identity.
 */
function testResultsInterval(data?: ProxyTestResultsResponse): number {
  return data && allFinished(data.items) ? 0 : TEST_POLL_MS
}

/**
 * The results of the tests of one pool by command id. Polled until every
 * test has ended (completed, failed, canceled or expired), then left alone.
 */
export function useProxyPoolTestResults(poolId: string, commandIds: string[]) {
  return useSWR<ProxyTestResultsResponse>(
    commandIds.length > 0 ? proxyPoolEndpoints.tests(poolId, commandIds) : null,
    (url: string) => get<ProxyTestResultsResponse>(url),
    {
      revalidateOnFocus: false,
      refreshInterval: testResultsInterval,
    }
  )
}
