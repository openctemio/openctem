### Security: threat model generation shares the heavy-read cap; scoped members see scoped totals

- `POST /api/v1/threat-models/generate` reads the organization's whole exposure graph, edges and findings. It now shares the per-organization cap of the other heavy reads (dashboard metrics, attack paths, exports): at most 4 run at once, the rest wait and get 503 `BUSY` if they give up. One member can no longer start generations in a loop and take the database connections.
- A member limited to some assets used to see a tenant-wide model's stored counters (`threats_total`, `threats_open`, `threats_mitigated`, `threats_covered`, `coverage_pct`), counted over threats on assets outside their scope. The model list, the model, its coverage view and the generate answer now count only the threats in their scope. Admins and unrestricted members still get the stored organization totals.
- Docs: server/docs/architecture/authorization-matrix.md
