# RFC-133: The AI harness (own loop, AI worker pool, scale on the job system, own tool sandbox)

| | |
|---|---|
| Status | Accepted (2026-10-28). Shipped in sdk-go (in review): the harness core (`pkg/harness`), pinned copies of the `openctem.analyze/v1` schemas, the playbook format `openctem.io/playbook/v1` with a sample, the eval harness and `openctem playbook init\|test`. The worker lives in the private repository `openctemio/ai-worker` (scaffold: configuration, playbooks with their golden sets, the eval gate in CI, a signed image). Designed: provider adapters, the sensorkit ai-worker role, the platform AI worker pool, the agent manifest and routing, safe rollout, the AI's own tool sandbox, memory and knowledge retrieval, inbound channels |
| Scope | sdk-go (harness, contract copies, playbooks, evals, CLI, ai-worker role), api (analyze command, grant builder, lanes and affinity, limits, routing, rollout, playbook content), `openctemio/ai-worker` (the AI worker image) and sensor, web (playbook editor, agent comparison), docs |
| Architecture | [ai-harness.md](../architecture/ai-harness.md), [ai-analyze-contract.md](../architecture/ai-analyze-contract.md) |
| Related | RFC-131 (AI analysis, analyze contract), RFC-132 (the AI agent as a service account with accountable owners), RFC-030 (scan work distribution), RFC-129 (shared fleet scheduling), RFC-040 (mutual distrust, signed jobs), RFC-094 (the platform depends on contracts only), RFC-099 (signed content catalog) |

## 1. Summary

An AI agent is a service account with accountable owners (RFC-132). This RFC defines the **harness** that does its
work. The harness is a loop that reads a masked context, calls a model, uses tools through the sensor runtime and
answers in a closed schema. It also defines how many harnesses (ours, a vendor's, an organization's own) form one
**pool** behind one contract.

Six rules:

1. **Our own thin loop in sdk-go.** It is small, Go, one signed binary, governed like a sensor. There is no general
   agent framework in the core, and the loop has no shell and no file editing. A spike measured the loop at
   about 1,850 lines and a 5.4 MB binary, against a ten-times-larger graph for the most complete Go agent framework.
2. **One framework-neutral contract family.** It is made of `openctem.analyze/vN` (jobs, results, outputs),
   `openctem.io/playbook/v1` (instructions), `openctem.ai.run/v1` (the run record) and `openctem.io/agent/v1` (the
   manifest). Any implementation that speaks it plugs in.
3. **Every AI worker is an ai-worker-role sensor.** It is paired, mTLS, takes signed jobs, sends a heartbeat, can be
   drained and auto-updates. It claims `analyze` jobs through the existing distribution: claim, lease, requeue, fair
   share, priority and expiry. There is no new queue, lock or workflow engine.
4. **The platform decides; agents execute.** Routing, data class, grant, placement, rollout and every write (as the
   AI agent's commands, with approvals) are decided by the platform.
5. **The AI's tools run with the sensor runtime's guarantees, on its own capacity.** The worker embeds the sensor
   runtime and claims its own signed tool tasks on a reserved interactive lane. Heavy tools go to the scan fleet.
   Intrusive tools always need a person.
6. **Nothing crosses tenants.** There is no shared memory, cache, sandbox or mask key. Institutional memory comes
   only from people's decisions.

## 1a. Terminology

The runtime is generic because later AI roles (remediation and fix pull requests, reports, threat hunting, ticket
routing) run on the same loop. The analyst is the first role, not the name of the runtime.

| Name | Meaning |
|---|---|
| AI agent | the platform principal (a service account with accountable owners, RFC-132) with a role |
| Role | what the agent does: `analyst` first; `remediator`, `reporter` and `hunter` later |
| Harness | the loop in sdk-go `pkg/harness` (with `contract`, `playbook`, `eval`) |
| AI worker | a sensor in the `ai-worker` role that runs the harness; the repository is `openctemio/ai-worker` |
| CLI | `openctem playbook init\|test` builds and tests a playbook (the artifact, like `openctem tool`); `openctem agent run\|build\|sign\|publish` builds an own agent (L2) |
| Naming convention | UI and docs say "AI agent" (two words, always with "AI", so it never reads as the retired sensor name). Data, API and audit use `ai_agent` (`actor_kind = ai_agent`). Code identifiers use `aiagent` / `AIAgent`. sdk-go's vocabulary check keeps banning a bare "agent" and the legacy sensor forms (`AGENT_*`, `agent_id`, `X-Agent-*`), allows the `ai` prefixed forms, and allows the one CLI word `agent` |
| Playbook | the instructions and checks of one kind of job; the sample `web-vuln-triage` is an analyst playbook |

Platform code and tables keep their current names (`ai_analysts` and friends) for now. Generalising the principal
(a role or persona column, the UI label "AI agents") is P1 of research/326 and needs its own change.

## 2. Motivation

- RFC-131 fixed the contract and a single-shot built-in executor. Multi-step analysis (verify with a tool, read
  related findings, cite evidence) needs a loop with policy before every tool call, hard budgets, a replayable
  record and evals. A component that reads hostile text from many organizations must not run that loop inside the
  API process.
- The volume needs many agents at once, and organizations want their own agents, their own models and air-gapped
  operation. One contract and one distribution path keep all of that a single system.
- An AI worker job must not wait behind busy scanners, and it must never get raw network access.

## 3. Options considered (scored in research/327 §3-4)

| Option | Result |
|---|---|
| Own thin loop in sdk-go | chosen: full control of policy, budgets, record and schema checks; two external modules; same runtime and sandbox as sensors |
| Strip an existing coding-agent harness | rejected: its core is a local shell, files and network for one trusted user; single-user sessions and config; other runtimes; heavy upstream churn |
| Build on a general agent framework | rejected for the core: large dependency graphs (40+ linked modules), frequent breaking releases, their own session stores beside our ledger. Offered instead as L2 templates (§10) that speak our contract |
| Only our MCP server (bring your own chat agent) | kept for interactive and assisting use, but not enough: no autonomous or scheduled runs, no playbooks or evals, no air-gapped autonomy |
| An external workflow engine for runs | rejected: it duplicates the command, claim and lease system; one candidate's license forbids offering it as a platform service |

## 4. The harness (sdk-go `pkg/harness`, shipped)

```mermaid
flowchart LR
  J[Verified job: kind, subject, grant, deadline] --> R[Registry: grant ∩ playbook, tier ≤ ceiling]
  B[Opened masked bundle] --> P[Prompt: platform rules, schemas, playbook, fenced fields]
  R --> L{Loop}
  P --> L
  L -->|request| M[Provider]
  M -->|tool calls| D[Decide each: policy, input schema, bound targets, hooks, budget]
  D -->|allowed, parallel| T[Tools]
  T -->|post-hooks, neutralize, truncate, fence| L
  D -->|refused: fixed code| L
  M -->|final answer| V[Closed schema, evidence resolves, risk-lowering cites, playbook evidence]
  V -->|refused once| L
  V --> O[result/v1 + record digest]
```

- **Provider interface.** There is one adapter per model API (Anthropic, OpenAI, Gemini, OpenAI-compatible for
  local and self-hosted models). Adapters translate only; they never execute or retry a tool. Credentials stay in
  the adapter, the egress forwarder or the model gateway. A replay provider replays a recorded run and plays scripted
  models in tests.
- **Registry and policy.** A tool is offered only if the signed grant and the playbook both name it and its tier is
  at or below the grant's ceiling; with no ceiling, nothing is offered. Every call is then decided before it runs:
  - the tool must be granted;
  - the arguments must satisfy the tool's input schema (closed by default);
  - a target argument must be a placeholder bound in the grant;
  - an intrusive tool is refused with `needs_approval`.

  Pre-tool hooks can only deny (a panicking hook denies). Post-tool hooks only transform output.
- **Budgets.** Steps, tool calls, tokens, seconds and cost are budgeted, never wider than the grant. After a budget
  stop the run gets exactly one final call with no tools.
- **Untrusted text.** Bundle fields and tool outputs are fenced with a per-run nonce (removed from the data itself),
  and invisible and format characters are stripped.
- **Answer.** The output must satisfy the closed schema of the kind. Every citation must name a bundle field or a
  successful tool output of this run. A risk-lowering verdict must cite evidence. The playbook's required evidence
  must be cited. One repair turn is allowed. Error codes are fixed strings.
- **Record.** `openctem.ai.run/v1` is an append-only JSON-lines record whose digest is reported in the result.
  Replaying with the recorded nonce produces the same digest.
- **Contract copies.** `pkg/harness/contract` holds byte-identical copies of `api/pkg/sensorproto/analyze/schemas`,
  pinned by sha256 in a test. A change is the same reviewed change on both sides (RFC-094: the platform never
  imports the SDK).

### 4.1 Where the harness lives

- `pkg/harness` stays in sdk-go. It shares the grant, scope, tool tiers, tool packs, claim and lease, the egress
  forwarder and the governor with the sensor runtime, so there is one compatibility range and one place for security
  fixes.
- Model-provider adapters do not go into sdk-go. They live in `openctemio/ai-worker` as plain HTTP clients, or later in
  a nested Go module, so sensor builds never pull vendor AI SDKs.
- Split `pkg/harness` into a nested module (a `go.mod` inside sdk-go, not a new repository) when one of these happens:
  an outside consumer needs the harness without the sensor runtime, the release cadences conflict, the dependency
  weight becomes a problem, or a separate team owns it.

## 5. Playbooks and evals (shipped)

- **Playbook** (`openctem.io/playbook/v1`, YAML). It declares:
  - name, version (semver, immutable once published), title and analyze kind;
  - output schema and model tier (`small` or `large`);
  - a match on sources and categories;
  - tools, which only narrow the grant;
  - required evidence (bundle fields that must be cited);
  - budgets, which only narrow the grant;
  - ordered steps, rules and instructions.

  Unknown keys are refused. The digest is over the exact bytes, and the platform pins it in the job (the
  `prompt_template` of the job is the playbook id and digest). Sample: `sdk-go/examples/playbooks/web-vuln-triage`.
- **Eval harness** (`pkg/harness/eval`). A golden case holds a masked bundle, the grant, recorded tool outputs,
  recorded model turns and the expected outcome.
  - Offline runs replay the model and are deterministic.
  - Live runs use a real provider while tools still return recorded outputs, so an eval never reaches a target.
  - Scores: agreement; risk-lowering precision (of the false-positive and severity-down outputs, the share also
    expected); injection cases, which pass only when no risk-lowering output comes out and no tool outside the
    grant ran.
  - Gate: injection cases 100 % (not configurable), agreement at least 0.9, risk-lowering precision 1.
- **CLI.** `openctem playbook init [--kind] <dir>` scaffolds a playbook and a golden case. `openctem playbook test [dir]`
  runs the gate and exits 1 on failure (CI step).

## 6. Executors and the AI worker pool

| Executor | Where | Kinds | Tools |
|---|---|---|---|
| In-process single-shot (RFC-131/132) | API worker | single-shot kinds | none |
| **Platform AI worker pool** | the AI worker image, run by the platform operator as platform-owned ai-worker sensors; in SaaS one sandboxed pod per job | every kind, multi-step | grant tools (§8) |
| Organization AI worker | the same image on the organization's infrastructure | every kind, including `tenant_only` data | grant tools |
| Own or external agents (§10) | anything that speaks the contract | kinds it declares | grant tools, conformance-checked |

Multi-step runs never execute in the API process. What the platform executor and the worker share is the
contract schemas, the playbook format (the api keeps a pinned copy of its schema with a drift test) and the golden
sets. The single-shot prompts become playbooks.

### 6.1 Agent manifest (`openctem.io/agent/v1`, a block of the sensor manifest)

The manifest declares:

- name, version and publisher (bound to the signing identity);
- implementation kind (harness, adapter, external) and runtime;
- contract ranges (`analyze`, `playbook`, `record`);
- the kinds and categories it serves;
- model providers and tiers, and whether it uses a bring-your-own key;
- its data class ceiling;
- where it runs (platform, tenant network, air-gapped);
- the tools it may request (the grant decides);
- its resource profile and concurrent runs;
- a self-reported cost (replaced by measured figures);
- required secrets (write-only console settings).

Enrollment, identity, heartbeat, drain, removal, auto-update and trust levels are the sensor ones (RFC-032,
RFC-040). Compatibility ranges live on the platform, so agent releases never need a platform release.

### 6.2 Routing (the platform decides)

1. **Filter** the workers that:
   - declare the kind and category;
   - have a contract range that includes the job;
   - accept the data class (and are tenant-controlled for `tenant_only`);
   - are allowed by the organization's agent, model and region policy;
   - are healthy, with free slots and acceptable pressure.
2. **Rank** by quality (override rate, eval score), then cost, then latency, then locality.
3. **Fall back** to the organization's agent, then the platform pool, then the single-shot executor for
   single-shot kinds, then refuse with a reason. Every decision gets an explainer row.

### 6.3 Safe rollout

```mermaid
stateDiagram-v2
  [*] --> Registered: installed (private registry: signature, digest pin, second-member approval)
  Registered --> EvalGate
  EvalGate --> Registered: fail
  EvalGate --> Shadow: pass on the platform's and the organization's golden sets
  Shadow --> Canary: agreement with people and with the live agent at or above the bar
  Canary --> Live: override rate not worse than control
  Canary --> RolledBack: regression or contract violation
  Live --> RolledBack: automatic on override-rate regression
  RolledBack --> Registered
```

- Shadow runs are recorded, never shown and never applied.
- A swap only changes routing weights, so in-flight runs finish on their version.

## 7. Scale on the job system

| Need | Mechanism |
|---|---|
| Queue and claim | `commands` with type `analyze`; tenant and shared claims; capability predicate `analyze:<kind>` |
| One run per subject × use case | synthetic host key `ai:<use_case>:<subject>` at claim + the run ledger's partial unique index at enqueue |
| Crash recovery | leases renewed by heartbeat; expired leases requeue; held work of a drained sensor includes `analyze` |
| Fairness | existing tenant and shared fair share; the round-robin key is the AI agent |
| Priority | critical: known-exploited, emerging and interactive; high: on-demand; normal: ingest triggers; low: campaigns and backfill |
| Big jobs | one analyze job per same-issue group, one command per finding at apply; claim-time chunking with RFC-030 phase 2 |
| Concurrency with people | row-version check on every command; conflict → re-plan, never overwrite |
| Provider rate limits | a shared token bucket per provider key; each claim carries a token lease in the signed limits |
| Tenant quotas | limit keys: runs per day, concurrent runs, tokens per day, cost per day; plus per-agent budgets (RFC-132) |
| Backpressure | per-class queue-age objectives; then delay low priority, route routine kinds to the small tier, fail over to another allowed provider; never widen the data class |
| Autoscaling | demand per lane published by the platform; the executor controller or a queue-driven autoscaler scales workers; per-cell pools in SaaS |
| Isolation on shared workers | one run per sandbox, bundle sealed to the claimer at claim, per-run mask key, prompt-cache key derived from the tenant |
| Approval floods | batch decisions, digests, a per-owner request cap, automatic pause of new risk-lowering requests above a pending threshold |

Capacity estimates and the load-test plan (100 workers × 50 tenants with fault injection) are in research/327 §8.3-8.4.
The expected bottleneck is the provider rate limit per key, not worker count.

## 8. The AI's own tool sandbox

RFC-132 states that the AI's hands are always the sensors. This RFC makes the meaning precise. The rule is
**"the hands are always the sensor runtime"**: every act on a target is a signed task that runs through the
per-task sandbox, the egress forwarder (scope, exclusions, placeholder resolution, politeness), the governor and
provenance. The AI worker is an ai-worker-role sensor built on that runtime, so it runs its own tool tasks:

| Piece | Design |
|---|---|
| Scope | the grant (role ∩ tool tier ∩ use case ∩ asset scope ∩ out-of-scope rules) is in the signed statement; each tool call becomes a tool task the platform validates against the grant and signs |
| Lane and affinity | tool tasks go on lane `interactive` with `affinity_sensor = <the requesting worker>`; the worker claims its own tasks first; another sensor may take one only after the affinity timeout; interactive capacity is reserved (scheduled and background work hold at most 80 % of a pool) |
| Sandbox | per-task namespaces, Landlock, seccomp and cgroup envelopes; in SaaS the worker pod is itself sandboxed (two layers); read-only root; no credentials |
| Egress | forwarder scope = the grant's bound targets; excluded names refused (signer-sourced exclusions); a placeholder resolves only through a binding |
| Politeness | AI tool tasks and scans share the same per-host keys and rate shares |
| Placement | the platform decides: a heavy tool profile, more targets than the threshold, or worker pressure → a normal fleet job, and the run waits in `waiting_tool` (lease released, resumed from the record on any worker); otherwise in-worker |
| Intrusive | never in-worker and never without a person: scan request → approval → fleet |

## 9. Memory, knowledge and channels

- **Memory.**
  - Session memory is the run state only.
  - Nothing is ever shared across tenants.
  - Optional per-organization institutional memory is built only from people's decisions (false-positive reasons,
    severity overrides, accepted risks, approved conventions), never from model output. It is versioned and audited,
    follows erasure of its source, can be toggled, and is retrieved through a scoped read tool with citations.
- **Knowledge retrieval.**
  - Sources are tenant documents (approved sources only, per-document provenance, masked, fenced as untrusted data),
    our documentation and vulnerability intelligence.
  - It starts with Postgres full-text and trigram search, which already exist. Vectors are added when measured.
    Vectors require a Postgres image with the vector extension built on the same libc, because a libc change alters
    text index collation.
  - Every use of retrieved text must be cited.
- **Channels.**
  - Console actions, events, schedules, chat and ticket comments, and mentions all become analyze jobs under the
    AI agent's identity.
  - Inbound webhooks must be signed. A mapped user can trigger but never authorize.
  - Replies go out through the existing notifier and integrations as the AI agent.
  - The AI never holds integration tokens.

## 10. Developer experience ladder

| Level | What | Runs on |
|---|---|---|
| L0 | console settings: preset, owners, instructions, thresholds, tool allowlist, approval rules, data class | our harness |
| L1 | playbooks authored in the console with a "try on these findings" preview and a diff, or locally with `openctem playbook init\|test` | our harness |
| L2 | an own agent in any language on `openctem.analyze/vN`: Go SDK first, Python and TypeScript later, framework templates whose tools call back into the worker's policy, `openctem agent run\|build\|sign\|publish`, conformance kit, CI templates | the organization's worker |
| L3 | an external agent through a thin adapter that is itself an ai-worker sensor (MCP, A2A, vendor API) | adapter |

The same rules hold at every level:

- AI service account and accountable owners;
- the same commands, approvals, audit and AI badge;
- a private registry with signature and digest pin plus second-member approval;
- shadow mode and an eval gate on the organization's own golden set;
- quotas and console observability.

## 11. Observability

- **Run record.** Every run has one.
- **Traces.** OpenTelemetry generative-AI spans (agent invocation, model call, tool execution, with token usage
  attributes) sit behind a switch while those conventions are still in development. Prompts never go into spans.
- **Cost.** It is computed from the platform's price table.
- **Per agent version and tenant:** runs, completion, error codes, latency, tokens, cost, override rate, eval score
  and denials per run, compared side by side in the console from precomputed figures.

## 12. Threat model and tests

| Threat | Control | Test |
|---|---|---|
| Injected text drives a tool call outside the grant | registry + policy before every call; the forwarder independently | `TestRunPolicyRefusesCallsOutsideTheGrant`; golden case "instructions in evidence" (shipped) |
| The model names a raw or foreign target | bound placeholders only; the forwarder resolves bindings | same test (shipped); forwarder test (planned) |
| Intrusive tool without a person | `needs_approval`, never offered | `TestGrantPolicyIntrusiveNeedsAPerson` (shipped) |
| Runaway loop or cost | budgets and one final call | `TestRunAModelThatNeverStopsIsBounded` (shipped) |
| Fabricated or missing evidence | citations must resolve; risk-lowering must cite; playbook evidence | evidence tests (shipped) |
| Output outside the schema | closed schemas | `TestRunProseOrExtraKeysAreRefused` (shipped) |
| Fence forgery, hidden characters | nonce removed from data; format characters stripped | `TestFenceCannotBeClosedFromInside` (shipped) |
| Cross-tenant prompt cache | tenant-derived cache key | `TestRunCacheKeyIsPerOrganization` (shipped) |
| Provider error text leaking | fixed codes | `TestRunProviderErrorTextNeverReachesTheResult` (shipped) |
| Contract drift | sha256-pinned copies | `TestSchemasArePinnedCopiesOfThePlatformContract` (shipped) |
| Another tenant's worker claims or opens a job | per-tenant claim; shared pool platform-owned only; bundle sealed at claim | integration (planned) |
| A malicious own or external agent | private registry, conformance, re-validation of every result, trust downgrade, data class ceiling | hostile-agent conformance (planned) |
| Duplicate runs overwrite each other | host key + unique index + row versions | race test (RFC-132) |
| The AI sandbox reaches out of scope | forwarder scope from the grant; signed exclusions | sandbox test (planned) |
| AI and scans overload one target | shared host keys and rate shares | politeness test (planned) |
| Interactive lane starved | reservation + affinity | lane test (planned) |
| Persistent injection through memory | memory only from human decisions | test: model output never creates a memory item (planned) |
| Poisoned document | source approval, provenance, fences, citation rule | retrieval tests (planned) |
| Spoofed chat trigger | signed webhooks; triggers never authorize | channel tests (planned) |

Authorization and tenant isolation are as in RFC-132. Workers hold jobs, never roles, and every write is a command
of the AI agent with its approvals.

## 13. Decisions

The full list D1-D36 is in research/327 §14. These are the ones that bind implementers:

- own loop in sdk-go;
- framework-neutral contracts;
- the command, claim and lease system for orchestration;
- multi-step runs only on ai-worker sensors;
- shared schemas and formats, not shared code;
- host key + unique index for one run per subject;
- provider token bucket and tenant limit keys;
- `openctem.io/agent/v1` in the sensor manifest;
- routing, shadow, canary and rollback in the platform;
- own tool sandbox on lane `interactive` with self-affinity;
- shared politeness;
- intrusive tools always need a person;
- no cross-tenant memory, and institutional memory from human decisions only;
- lexical retrieval before vectors;
- permissive licenses only in the core.

## 14. Plan

- **Shipped (sdk-go, in review):**
  - harness core, contract copies, playbook format and sample;
  - eval harness and `openctem playbook init|test` with a golden set.
- **Scaffolded:** `openctemio/ai-worker` (private): `cmd/ai-worker` wires configuration and playbook pin checks and marks where the claim and lease, the signed grant and the result plug in; `playbooks/` with golden sets and the CI eval gate; distroless non-root multi-arch image, signed (cosign keyless) with SBOM; security gate and release pipeline as in sensor.
- **Next:**
  1. provider adapters with tool use;
  2. the sensorkit ai-worker role (claim, digests, sealed bundle, job-token read tools, tool tasks, signed results,
     hostile-model conformance);
  3. platform:
     - analyze command and the analyst-role grant profile;
     - grant builder;
     - interactive lane and affinity claim;
     - shared host keys;
     - drain including analyze;
     - AI limit keys;
     - provider token bucket;
  4. playbook content in the catalog, single-shot prompts as playbooks, golden sets in CI;
  5. platform AI worker pool deployment;
  6. routing, manifest, shadow runs, generative-AI spans, per-agent dashboard, approval flood control;
  7. console playbook editor.
- **Later:**
  - autoscaling and per-job sandboxed pods with a model gateway;
  - adapters, Python and TypeScript SDKs, templates, publishing;
  - canary and automatic rollback;
  - institutional memory and retrieval;
  - inbound channels;
  - a no-network evidence parser;
  - compaction, verification subruns, a critic step and model escalation.
