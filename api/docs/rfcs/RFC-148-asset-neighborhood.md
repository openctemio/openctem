# RFC-148: Asset neighborhood and lineage graph read

| | |
|---|---|
| Status | Implemented (2026-11-04) |
| Scope | api (neighborhood endpoint on the graph reader), web (relationships graph on the shared flow canvas) |
| Architecture | [asset-relationships.md](../architecture/asset-relationships.md) |
| Related | RFC-042 (asset inventory, related groups), [easm.md](../architecture/easm.md#4o-discovery-lineage-built) (discovery lineage) |

## 1. Problem

The asset page's relationship graph drew one hop, from the flat relationship
list, only when the asset had at most 30 edges, with a hand-drawn SVG. An
address showed the name that resolves to it but not the domain that contains
the name, so the reader could not see where the address comes from. Larger
neighborhoods had no graph at all.

## 2. Decisions

1. **One neighborhood read**, `GET /api/v1/assets/{id}/neighborhood`:
   both directions (or one), depth 1 to 3 (default 2), asset-type and
   relationship-type filters, at most 300 assets (default 150). A breadth
   first walk, one statement per hop for the whole frontier, with a visited
   set (cycles end the walk).
2. **Clusters instead of cut-offs**: a group of more than 8 siblings (one
   anchor, one relationship type, one direction) is one counted node with its
   count per asset type, and is not walked. What does not fit the node cap is
   counted the same way and the answer says `truncated`. A cluster is paged
   with the existing related-groups endpoint.
3. **Lineage always drawn**: the answer carries the asset's discovery lineage
   (the existing lineage reader, up to 5 ancestors) and its visible ancestors
   are nodes even beyond the depth, outside the node cap.
4. **Out-of-scope neighbors are counts.** A related asset outside the
   caller's data scope is never returned and never walked through; each
   visible node carries `hidden_neighbors`, over all its edges whatever the
   filters. Redacted stubs inside a walk would expose the shape of the graph
   beyond the scope; the lineage keeps its redacted hops, as before.
5. **Cost bounds**: depth and node caps, a read-only transaction with a 3 s
   statement timeout per hop, a per-user rate limit (2/s, burst 30). Both
   directions use existing indexes; measured at 1 M assets and 3.2 M edges
   (architecture doc).
6. **Web**: the graph uses the shared flow canvas (keyboard model, focus
   ring, light and dark tokens), lineage highlighted, clusters expandable,
   expand-from-node, depth selector, legend by type; the grouped list remains
   the complete accessible view, and the graph is offered whatever the number
   of edges.

## 3. Not in this RFC

Relationship-based scan expansion, the organisation-wide estate map, path
queries between two assets, and a relation predicate in the query language
are separate work on the same reader.
