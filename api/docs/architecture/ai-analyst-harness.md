# AI analyst harness

Design: [RFC-133](../rfcs/RFC-133-ai-analyst-harness.md). Contract: [ai-analyze-contract.md](ai-analyze-contract.md)
(RFC-131). Principal and governance: RFC-132.

The harness is the loop that does an AI analyst's work for one `openctem.analyze/v1` job. It lives in the sensor SDK
(`github.com/openctemio/sdk-go/pkg/analyst`) and runs inside an **analyst worker**: a sensor in the analyst role,
run by the platform operator (the platform analyst pool) or by an organization. Multi-step runs never execute in the
API process. The API keeps only the single-shot executor (one model call, no tools).

## Shipped vs planned

| Part | State | Where |
|---|---|---|
| Harness loop, provider interface, replay provider, tool registry, grant policy, hooks, budgets, fenced untrusted text, closed output schema with evidence checks, run record, result rendering, model tiers | shipped in sdk-go (in review) | `sdk-go/pkg/analyst` |
| Copies of the analyze/v1 schemas, pinned by sha256 | shipped in sdk-go (in review) | `sdk-go/pkg/analyst/contract` (source: `api/pkg/sensorproto/analyze/schemas`) |
| Playbook format `openctem.io/playbook/v1` + sample | shipped in sdk-go (in review) | `sdk-go/pkg/analyst/playbook`, `sdk-go/examples/playbooks/web-vuln-triage` |
| Eval harness and `openctem agent init\|test` | shipped in sdk-go (in review) | `sdk-go/pkg/analyst/eval`, `sdk-go/internal/agentcli` |
| Provider adapters with tool use; sensorkit analyst role; hostile-model conformance | planned | sdk-go |
| `analyze` command type, analyst grant profile, grant builder, interactive lane + affinity, shared host keys, AI limit keys, provider token bucket | planned | api |
| Platform analyst pool deployment, agent manifest, routing, shadow/canary/rollback, playbook catalog content, editor | planned | api, web, deploy |
| Institutional memory, knowledge retrieval, inbound channels | planned | api, web |

## How a run works

1. **The platform builds the job.** It checks admission (the analyst is active, it has owners and a fresh
   attestation, budgets, data class, quotas). It then builds the masked bundle, the grant (role ∩ tool tier ∩ use case
   ∩ asset scope ∩ out-of-scope rules) and the playbook reference with its digest. It signs the statement and enqueues
   an `analyze` command whose synthetic host key `ai:<use_case>:<subject>` keeps one run per subject.
2. **An analyst worker claims it** through the normal sensor distribution (lease, heartbeat, requeue on crash), then
   verifies the signature and digests and opens the sealed bundle.
3. **The loop runs.** Each turn:
   - The model is called with the platform rules, the output schemas, the playbook, the fenced bundle fields and
     only the tools the grant and the playbook both allow.
   - Every requested tool call is decided before it runs: granted tool, input schema, target placeholder bound in
     the grant, tier at or below the ceiling. Intrusive tools are refused with `needs_approval`.
   - Hooks may deny, and the tool-call budget is checked.
   - Allowed calls run in parallel up to a limit. Their output is redacted, neutralized, truncated and fenced with
     the run's nonce.
4. **The answer is validated.** It must satisfy the closed schema of the kind. Every citation must resolve to a
   bundle field or a tool output of this run, a risk-lowering verdict must cite evidence, and the playbook's
   required evidence must be cited. One repair turn is allowed. After a budget stop the run gets exactly one final
   call without tools.
5. **The result goes back.** The worker returns `openctem.analyze.result/v1` with the run record digest. The
   platform validates it again, turns placeholders back into values, and applies the suggestions as the AI analyst's
   normal commands. Risk-lowering changes become requests that a person decides.

## Tools

- **Platform read tools** use a job token scoped to the subject: the same read paths a person uses.
- **Tool-pack tools** run as signed tool tasks. They run in the worker's own per-task sandbox, on lane
  `interactive`, claimed by the same worker (self-affinity). The egress forwarder enforces the grant's targets and
  the excluded names, and politeness keys are shared with scans. Heavy tools are placed on the scan fleet, and the
  run waits.
- **MCP servers** are allowed only when the organization approved them, pinned by definition digest.
- **There is no shell and no code execution.**

## Playbooks and evals

```bash
openctem agent init --kind triage.v1 ./my-triage   # playbook.yaml + golden/01-example.json
openctem agent test ./my-triage                    # validate, run the golden set offline, apply the gate
```

- **Gate:** every injection case passes, agreement is at least 0.9, and risk-lowering precision is 1.
- **Offline runs** replay recorded model turns and tool outputs. They are deterministic and never reach a target.

## Security properties

- A fully steered model can only call granted tools on bound targets within budgets, and its answer must fit a
  closed schema with resolvable evidence.
- Writes happen only through the analyst's commands and approvals (RFC-132).
- Nothing crosses tenants. There is one run per sandbox. Prompt-cache keys are derived from the tenant. Mask keys
  are per run. Memory is never shared.
- Provider and tool text never reaches a result's error code.
- The worker's schemas are byte-identical copies of the platform's, pinned by digest.

## Key files

- `sdk-go/pkg/analyst/run.go` (loop), `policy.go`, `tool.go`, `budget.go`, `fence.go`, `record.go`, `result.go`,
  `provider.go`, `router.go`
- `sdk-go/pkg/analyst/contract/contract.go`, `sdk-go/pkg/analyst/playbook/playbook.go`, `sdk-go/pkg/analyst/eval/eval.go`
- `api/pkg/sensorproto/analyze/` (contract source), `api/internal/app/aianalysis/` (single-shot executor, RFC-132)
