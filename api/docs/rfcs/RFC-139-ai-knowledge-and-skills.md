# RFC-139: Knowledge and skills for AI agents

| Field | Value |
|---|---|
| Status | Accepted (2026-10-31). Implemented: organization knowledge sources (upload), document versions with second-person approval, credential refusal and prompt-injection quarantine at ingest, team visibility and data class, lexical retrieval scoped by the AI agent, `kb:<n>` citations and the retrieval record in built-in triage runs. Designed: platform knowledge packs, decision memory, skills, URL and Git sources, retrieval tools for AI workers, vector retrieval, paired shadow measurement |
| Builds on | RFC-099 (content packages), RFC-131 (analyze contract), RFC-132 (AI agent principal), RFC-133 (harness, §9 memory and knowledge), RFC-135 (revisions) |
| Architecture | [ai-knowledge.md](../architecture/ai-knowledge.md) |

## 1. Summary

An AI agent decides better when it knows how the organization works. This RFC decides what context an AI agent gets,
where each kind lives, how it is retrieved without crossing an organization or a data scope, and how a poisoned
document is kept from deciding anything.

Four kinds of context, four homes:

| Kind | Examples | Home |
|---|---|---|
| Live platform data | the finding, asset, criticality, owners, SLA, KEV, EPSS, scan history | the bundle and read tools; never copied into a text index |
| Platform knowledge | CWE, CAPEC, ATT&CK, CTEM concepts, our documentation, remediation per technology and version | signed, versioned content packages (RFC-099 artifact kind `knowledge`) |
| Organization knowledge | runbooks, policies, architecture notes, naming conventions, crown-jewel notes | knowledge sources an administrator approves (this RFC, shipped) |
| Decision memory | the organization's own false-positive verdicts with reasons, severity overrides, accepted risks, routing | items projected from people's decisions; opt-in, default off |

Procedures are **playbooks** (RFC-133 §5). A playbook references **skills**: reusable units with instructions,
allowed tools (narrowing only), examples, an output template, knowledge bindings and golden cases.

## 2. Motivation

The built-in executor triages from the finding and its asset only. It cannot know that hosts named `*.stg.*` hold no
customer data, that a WAF fronts every public application, or how this organization patches. People keep that in
runbooks and in their own past decisions. Giving it to the model raises the quality of triage and remediation
proposals, and it is the largest new attack surface of the AI: text that a person outside the security team can
edit now reaches the model.

## 3. Organization knowledge (shipped)

- **Source**: name, visibility (`organization`, or `teams`: only AI agents that are members of one of the listed
  teams), data class (`internal`, or `restricted`, masked strictly), status (`pending`, `approved`, `rejected`,
  `disabled`). Visibility, class and teams are fixed at creation: changing them would widen retrieval without an
  approval.
- **Document version**: title, text (plain text or Markdown, at most 256 KB), sha256, status. Editing a document adds
  its next version as `pending`; the approved version keeps serving until the new one is approved. One approved
  version per document (unique index).
- **Chunk**: a section of a version (split at headings, filled with paragraphs to about 1,200 characters), the unit
  of retrieval and citation.
- **Ingest**: normalize (valid UTF-8, no control or invisible format characters), refuse a document that holds a
  credential (the line is named, nothing is stored), split, and quarantine a version whose text matches a known
  prompt-injection pattern.
- **Approval**: approving a source approves its pending versions. The person who added the source or a pending
  version cannot approve it; the organization owner may, with a recent sign-in, recorded as a self-approval.
  Quarantined versions need an explicit acknowledgement. Disabling applies at once (tightening needs no second
  person).
- **Quotas**: 50 sources, 2,000 documents and 50 MB of text per organization; 400 chunks per document.
- **Permissions**: `ai_knowledge:read` (names, states, counts; never text) and `ai_knowledge:manage` (every change,
  and previewing what an AI agent would retrieve, which shows text). Owner and administrator roles hold both. AI agents
  never hold `ai_knowledge:*` (deny list).

## 4. Retrieval (shipped: lexical)

- **Who searches.** Always an AI agent: the tenant and the agent come from the run (or, for a preview, from an agent
  of the caller's own organization). No search parameter names a tenant, a source, an index or a scope. The rule is
  tested with a foreign organization's ids and words in the query.
- **What it may see.** Approved source and approved version; class within the agent's data-class ceiling (none under
  `public`, restricted only under `restricted`); organization visibility, or the agent's own active team membership.
- **How.** Postgres full-text search with the language-neutral `simple` configuration (organizations write
  Vietnamese and English, and English stemming damages Vietnamese and identifiers), title weighted above body, plus
  trigram similarity on the section title. The query is the finding's terms joined with `or` through
  `websearch_to_tsquery`, which never fails on user syntax; terms are letters and digits only.
- **Single-shot runs.** Before the model call the platform retrieves up to five excerpts for the finding (title,
  CVE, CWE, tool, rule, asset name, type and environment). The query never comes from model output.
- **Vectors** come only when a retrieval golden set measures lexical recall@5 below 0.8. Then: pgvector on our own
  alpine Postgres image (another libc changes text collation), an embedding index derived from the chunk rows that
  can be dropped and rebuilt at any time, reciprocal-rank fusion with the lexical list.
- **Record.** The run stores its retrieval mode (`none`, `lexical`, `hybrid`, `vector`) and index version, and one
  row per excerpt it saw: run-local ordinal, chunk, document version digest, score, whether the output cited it. No
  text: deleting a document erases it, and the citation then shows the digest and "deleted".

## 5. Use in the prompt and in decisions (shipped)

- Excerpts are masked with the run's own key (the same placeholder for a host named in the finding and in a runbook),
  restricted ones strictly; an excerpt carrying a credential is dropped; injection patterns mark the bundle; each
  excerpt sits inside the run's nonce fence, labeled `kb:<n>` with its last change date, after the finding fields.
  The bundle digest covers the excerpts.
- The evidence reference pattern of `openctem.analyze/v1` gains `kb:<n>` (additive: older outputs stay valid). A
  `kb:` reference resolves only to an ordinal the run really sent.
- **Knowledge is evidence about the organization, never about the finding.** A suggestion whose only resolved
  evidence is knowledge never changes the finding: it is written as a comment with the reason
  `knowledge_only_evidence`. Risk-lowering stays a request a person decides in every case (RFC-132).
- The AI agent's comment ends with a `Sources:` line naming the cited organization-wide documents; a team document is
  named only as "team knowledge document", because a reader of the finding may not be in that team. The run detail
  (`GET /api/v1/ai/runs/{id}`) lists every excerpt; names of a team source are withheld from a viewer outside its
  teams unless they hold `ai_knowledge:manage`.

## 6. Platform knowledge packs (designed)

RFC-099 packages with artifact kind `knowledge`: Markdown documents with front matter (`id`, `title`, `kind`, `tags`
such as `cwe:79` or `tech:nginx`, `lang`, `reviewed_at`), signed, countersigned, in the signed index and the
revocation list, installed instance-wide as public-class rows without a tenant column, usable offline. First packs:
CWE and CAPEC, ATT&CK, CTEM concepts and documentation, remediation per technology and version, what each built-in
scanner rule family checks. CVE, KEV, EPSS and exploit status stay live data (bundle and an intel read tool), never a
pack.

## 7. Decision memory (designed)

Items projected from people's decisions (false-positive approvals with the decider's note, severity decisions,
accepted risks, duplicate links and reassignments by people), with scope keys (rule, CVE, CWE, tool, finding type,
asset group). Never from model output: when a person decides a request an AI agent wrote, the item keeps the decision
and the person's own note, never the AI's reason. Opt-in per organization (default off) with a preview; each item can
be deleted; erasure follows the source decision. Retrieved by exact scope match first, at most three per run, cited as
`mem:<n>`; the same "never decides alone" rule applies, plus a per-decider share cap.

## 8. Skills (designed)

- `openctem.io/skill/v1`: a folder with `SKILL.md` (closed YAML front matter: name, version, description,
  `applies_to`, tools, knowledge bindings, output schema and template, required evidence, budgets; Markdown
  instructions), examples and golden cases.
- A playbook references skills by name and version. Multi-step runs see only the skill index (name and description)
  and load a body with one recorded tool call; single-shot runs get at most three skills the platform selects by
  `applies_to`.
- Platform skills are RFC-099 packages (artifact kind `ai-skill`); organization skills are private catalog content
  approved by a second member. An agent revision pins `skill@version#digest`; a new skill version reaches an agent only
  through the revision lifecycle (eval gate, shadow, canary; RFC-135).

## 9. Retrieval for AI workers (designed)

Platform read tools over the job token: `knowledge.search {query, limit ≤ 8}`, `memory.search {query, limit ≤ 3}`,
`skill.load {name}`. The same retriever and the same foreign-organization test; no tenant, scope or index argument.

## 10. Measuring value (designed)

Paired shadow runs (same subject, knowledge on and off) compare override rate, agreement with the final human
decision, risk-lowering precision, minutes to decision and cost per finding, precomputed per agent × revision ×
retrieval mode. Per-document influence (decisions agreed vs overridden when it was cited) flags wrong or poisoned
documents on the Knowledge page.

## 11. Threat model and tests

| Threat | Control | Test |
|---|---|---|
| Retrieval across organizations | tenant from the run only, every statement filters on it, composite keys | DB: another organization's ids and words in the query return nothing of it; an agent presented with another tenant is refused |
| Retrieval outside the agent's scope | team membership and class ceiling in SQL | DB: team source hidden until the agent joins; restricted only under a restricted ceiling; nothing under public |
| Injection in a document | quarantine, explicit acknowledgement, fence, masking | DB and unit tests |
| Poisoned document deciding | knowledge-only evidence becomes a comment | executor DB test |
| Silent edit of approved text | edits are pending versions; editor cannot approve | DB test |
| Credentials in documents | refused at ingest; dropped at prompt time | DB and unit tests |
| Self-approval | second person, owner exception recorded | DB test |
| Citation of text the run never had | `kb:` resolves only to sent ordinals | executor DB test |
| Team document names through citations | names withheld outside the teams | DB test |
| Erasure | cascade deletes; citations keep ids and digests only | DB test |

## 12. Decisions

| # | Decision |
|---|---|
| D1 | Live data stays tools and bundle; never a knowledge index |
| D2 | Platform knowledge as RFC-099 packages, kind `knowledge` |
| D3 | Organization knowledge: sources → document versions → chunks; second-person approval; edits pending |
| D4 | Credentials refused; injection quarantined |
| D5 | Lexical first (`simple` full-text + trigram); vectors only when measured, derived and rebuildable |
| D6 | Retrieval scope from the run only; no tenant or scope argument anywhere; foreign-organization test |
| D7 | Knowledge never decides alone; risk-lowering stays a person's decision |
| D8 | Citations `kb:<n>` recorded per run without text; retrieval mode and index on the run |
| D9 | Decision memory opt-in, from people's decisions only |
| D10 | Skills `openctem.io/skill/v1`, pinned in revisions, eval-gated |

## 13. Plan

- **Done:** §3, §4 (lexical), §5; console Knowledge sources section.
- **Next:** worker retrieval tools (§9); decision memory (§7); skill format and playbook references (§8); packages of
  kind `knowledge` and `ai-skill` with the first packs (§6); URL and Git sources through `pkg/httpsec`; per-agent
  bindings in the revision spec; paired shadow (§10); quota limit keys.
- **Later:** vectors (measured), Confluence, decision-memory anomaly signal.
