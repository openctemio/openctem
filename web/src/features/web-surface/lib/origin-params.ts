import type { WebEndpointParamResponse, WebEndpointResponse } from '@/lib/api/generated'

/** One parameter of one endpoint, flattened for the Parameters table. */
export interface ParamRow extends WebEndpointParamResponse {
  endpointId: string
  method?: string
  pathTemplate?: string
}

/** Flattens each endpoint's parameter list into rows (names only, never values). */
export function flattenParams(
  endpoints: WebEndpointResponse[],
  lists: (WebEndpointParamResponse[] | undefined)[]
): ParamRow[] {
  const rows: ParamRow[] = []
  endpoints.forEach((e, i) => {
    for (const p of lists[i] ?? []) {
      rows.push({ ...p, endpointId: e.id ?? '', method: e.method, pathTemplate: e.path_template })
    }
  })
  return rows
}
