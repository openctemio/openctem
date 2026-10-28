# Glossary: one name per concept

This page is the single source of truth for product names. Every layer uses the
name in its column: the web console (en and vi), the public docs, the API, the
database and the code. A new feature takes its words from here. A term that is
missing is added here in the same PR that introduces it.

When a layer still uses another name, the **Still differs** column says where.
Those are known gaps, renamed in their own PRs; do not copy them into new code.

Related one-name-per-concept pages: [scans, scan workflows, runs and CI](architecture/scan-naming.md),
[sensors](architecture/sensors.md). The public glossary for users is
[docs.openctem.io/overview/glossary](https://docs.openctem.io/overview/glossary/).

## Style per layer

| Layer | Style | Example |
|---|---|---|
| Console text (en) | Sentence case for labels, buttons, headings and nav. American spelling. No abbreviations (organization, not org; repository, not repo). No raw enum values or identifiers. | "Scan workflows", "Suppression rules" |
| Console text (vi) | The Vietnamese column below. A product noun without a good Vietnamese word stays English in lower case in prose and capitalised at the start of a label (sensor, Sensor). | "Lần chạy", "Sensor" |
| Docs (docs.openctem.io) | Same words as the console. URL slugs are kebab-case nouns. | `/scanning/scans-and-runs/` |
| API paths | `/api/v1/` + plural kebab-case nouns; actions as a trailing verb segment (`/scans/{id}/trigger`). Path parameters `{id}` or `{snake_id}`. | `/api/v1/scan-workflows` |
| JSON fields, query keys | snake_case. | `scan_run_id` |
| Permission keys | `area:resource:verb`, snake_case segments, verbs `read`, `write`, `delete`, plus a named action where needed (`approve`, `trigger`). | `scans:workflows:write` |
| Module ids | snake_case. | `scan_workflows` |
| Audit actions, domain events | `resource.verb_past`, singular resource. | `finding.created` |
| DB tables and columns | snake_case, plural tables, `<thing>_id` foreign keys, booleans `is_<adjective>` or `has_<noun>`. | `scan_runs.scan_id` |
| Go | Packages one lower-case word (`scanrun`), exported types without stutter where new (`scanrun.Run`). | `pkg/domain/scanrun` |
| TypeScript | camelCase values, PascalCase types and components, kebab-case files. | `scan-run-drawer.tsx` |
| Env vars | `AREA_SETTING` upper snake case, area prefix from the env registry; `SENSOR_*` for sensors. | `SENSOR_API_URL` |
| CLI | `openctem <noun> <verb>`, kebab-case flags. | `openctem playbook test` |
| Container images | `ghcr.io/openctemio/<repo or component>`. | `ghcr.io/openctemio/sensor` |

## Organizations and people

| Term | Meaning | Console (en) | Console (vi) | API | Database | Code | Still differs | Retired names |
|---|---|---|---|---|---|---|---|---|
| Organization | The unit of isolation: its own members, assets, findings, sensors, integrations and audit log. | Organization | Tổ chức | `/api/v1/organization/*` (the current organization) | `tenants`, `tenant_id` | `pkg/domain/tenant` | "tenant" stays in the database, Go and a few env vars as the internal word. `/api/v1/tenants/{tenant}/*` and `/api/v1/admin/tenants/*` are user-visible and are proposed for renaming. | tenant (in text a person reads), team (for the organization), workspace, project |
| Member | A person with a role in an organization. | Member | Thành viên | `/api/v1/organization/members` | `tenant_members` | `tenant.Membership` | | |
| Team | A group of members that is assigned assets. A member sees the assets (and their findings) of their teams. | Team | Nhóm | `/api/v1/groups` | `groups` | `pkg/domain/group` | API and permission keys say group (`team:groups:*`); the `team:*` permission family otherwise means organization administration. | access group (docs headword before this page) |
| Role | A named set of permissions given to a member. | Role | Vai trò | `/api/v1/roles` | `roles` | `pkg/domain/role` | | permission set (removed) |
| Platform administrator | An operator account of the installation, with no organization data access. | Platform administrator | Quản trị viên nền tảng | `/api/v1/admin/*` | `admin_users` | `pkg/domain/admin` | | |
| Platform console | The operators' own web application. | Platform console | Bảng điều khiển nền tảng | admin plane | | `console/` | | admin console (in text) |
| Console | The web application organizations use. | (product name) | | | | `web/` | Image `openctem-web`, Helm key `ui`, Compose service `web`. | UI (as a product name) |

## Assets and scope

| Term | Meaning | Console (en) | Console (vi) | API | Database | Code | Still differs | Retired names |
|---|---|---|---|---|---|---|---|---|
| Asset | Anything an organization owns that can be attacked (domain, IP address, host, service, repository, cloud account, ...). | Asset | Tài sản | `/api/v1/assets` | `assets` | `pkg/domain/asset` | | target (for a stored asset) |
| Asset inventory | The list of an organization's assets. | Asset inventory | Kho tài sản | `/api/v1/assets` | | | | |
| Asset group | A named set of assets. | Asset group | Nhóm tài sản | `/api/v1/asset-groups` | `asset_groups` | `pkg/domain/assetgroup` | | |
| Target | What one scan or task is pointed at: an asset or an address range, at run time. | Target | Mục tiêu | `targets` fields | | | vi also uses "đích" in scans; use "mục tiêu". | |
| Scope | What an organization may test: scope targets and exclusions. | Scope | Phạm vi | `/api/v1/scope` | `scope_targets`, `scope_exclusions` | `pkg/domain/scope` | | scope config |
| Scoping | The CTEM stage that sets scope and business context (nav group). | Scoping | Xác định phạm vi | `/api/v1/scoping` | | `pkg/domain/scoping` | | |
| Crown jewel | An asset marked as business-critical. | Crown jewel | Tài sản trọng yếu | asset field | | | | |

## Findings and remediation

| Term | Meaning | Console (en) | Console (vi) | API | Database | Code | Still differs | Retired names |
|---|---|---|---|---|---|---|---|---|
| Finding | One weakness on one asset, from a scan, an import or an integration; de-duplicated by fingerprint. Kinds: vulnerability, secret, misconfiguration, code weakness, compliance. | Finding | Phát hiện | `/api/v1/findings` | `findings` | `vulnerability.Finding` | The Go domain package is `pkg/domain/vulnerability` and the service `finding.VulnerabilityService`. | issue (for a finding), result |
| Vulnerability | A known weakness in software, usually with a CVE id, from the vulnerability catalog. A finding may point at one. | Vulnerability | Lỗ hổng | `/api/v1/vulnerabilities` | `vulnerabilities` | `pkg/domain/vulnerability` | | |
| Exposure event | An attack-surface change that is not a vulnerability: an open port, a public bucket, an expiring certificate. | Exposure event | Sự kiện phơi nhiễm | `/api/v1/exposures` | `exposure_events` | `pkg/domain/exposure` | "Exposures" is also the nav section that lists findings by kind. | |
| Severity | The impact of a finding as rated by its source (critical, high, medium, low, info). | Severity | Mức độ nghiêm trọng | `severity` | `severity` | | | |
| Priority | A finding's ranking for remediation, computed with an explanation. Not severity. | Priority | Mức ưu tiên | `priority` | | | | |
| Criticality | How important an asset is to the business. | Criticality | Mức độ quan trọng | `criticality` | `criticality` | | | |
| Suppression rule | An approved rule that marks matching findings as false positive or accepted risk. | Suppression rule | Quy tắc chặn | `/api/v1/suppressions` | `suppression_rules` | `pkg/domain/suppression` | The nav item says "Exceptions"; vi text says "loại trừ", the word for a scope exclusion. | exception (for a suppression rule) |
| Remediation task | A unit of fix work on one or more findings; a finding belongs to at most one open task. | Task | Công việc | `/api/v1/remediation/tasks` | `remediation_tasks` | `pkg/domain/remediation` | vi also uses "nhiệm vụ" and "tác vụ". | |
| Remediation campaign | A set of remediation tasks with an owner, a deadline and tracked progress. | Campaign | Chiến dịch | `/api/v1/remediation/campaigns` | `remediation_campaigns` | `pkg/domain/remediation` | | |
| Ticket | An item in an external tracker (Jira and others) linked to a finding or a task. | Ticket | Ticket | `ticket_*` fields | `ticket_links` | `pkg/domain/ticketlink` | Some text says "issue" for a ticket; use "ticket" unless naming the tracker's own word. | |
| Retest | A re-check of a finding by a sensor, typically after a fix. | Retest | Kiểm tra lại | `/api/v1/findings/{id}/retests` | `retests` | `pkg/domain/retest` | | |
| Validation | Confirming that a finding is exploitable, or fixed, with a safe check, recording the evidence. | Validation | Kiểm chứng | `/api/v1/validation` | | | Permission `validation:*` also gates pentest. | |
| Automation | An event rule: when an event happens and conditions hold, take actions. | Automation | Tự động hóa | `/api/v1/workflows`, `/api/v1/workflow-runs` | `automations`, `automation_runs` | `pkg/domain/automation` | API path, module id `workflows`, some console text ("Create workflow") and Go types (`automation.Workflow`) still say workflow. | workflow (for an automation) |

## Scanning

Model: a **scan** has **runs**; a run has **steps**; a step has **tasks**.
Details in [scan-naming.md](architecture/scan-naming.md).

| Term | Meaning | Console (en) | Console (vi) | API | Database | Code | Still differs | Retired names |
|---|---|---|---|---|---|---|---|---|
| Scan | A scan configuration: targets, scan workflow and schedule. | Scan | Quét (cấu hình quét) | `/api/v1/scans` | `scans` | `pkg/domain/scan` | | |
| Scan workflow | A reusable graph of steps (which capabilities and tools run, in which order). | Scan workflow | Quy trình quét | `/api/v1/scan-workflows` | `scan_workflows` | `pkg/domain/scanworkflow` | | pipeline, pipeline template |
| Run | One execution of a scan. Kinds: scan, quick, retest, validation, test, connector, system. | Run | Lần chạy | `/api/v1/scan-runs` | `scan_runs` | `pkg/domain/scanrun` | | pipeline run, job |
| Step | One step of a run. | Step | Bước | in the run | `scan_run_steps` | `scanrun.StepRun` | | step run |
| Task | One unit of sensor work of a step, for a chunk of targets. | Task | Tác vụ | `/api/v1/scan-runs/{id}/tasks` | `commands` | `pkg/domain/command` | Sensor pages, sensor events, the admin console and some settings say "job"; the sensor protocol says command. | job (in text a person reads) |
| Command | Any instruction the platform queues for a sensor: a task, a configuration update, a health check. A task is a command. | Command | Lệnh | sensor protocol `/commands` | `commands` | `pkg/domain/command` | | |
| Quick scan | One capability on up to 1,000 targets without saving a scan. | Quick scan | Quét nhanh | | | | | |
| Capability | One kind of act a tool performs, named `verb.object@major` (for example `discover.subdomains@1`). Passive, active and intrusive acts are separate capabilities. | Capability | Năng lực | `/api/v1/capabilities` | | `pkg/domain/capability` | Some taxonomy ids are not verb.object (`sast.code`, `sbom.generate`). | |
| Tool | A scanner or other program a sensor runs for a capability. | Tool | Công cụ | `/api/v1/tools` | `tools` | `pkg/domain/tool` | | scanner (for a tool) |
| Scan profile | Saved tool settings reused by scans. | Scan profile | Hồ sơ quét | `/api/v1/scan-profiles` | `scan_profiles` | `pkg/domain/scanprofile` | | |
| Scan zone | A set of address ranges plus the sensors that can reach them. | Scan zone | Vùng quét | `/api/v1/scan-zones` | `scan_zones` | `pkg/domain/scanzone` | Permission `sensors:zones:*`. | |
| Scan window | When scans may run. | Scan window | Khung giờ quét | `/api/v1/scan-windows` | `scan_windows` | `pkg/domain/scanwindow` | | |
| Content pack | A signed, immutable archive of scanner content (templates, rules, a wordlist), named by its digest. | Content pack | Gói nội dung | `/api/v1/content-packs` | `content_packs` | `pkg/domain/contentpack` | `/api/v1/content/packages` (content catalog) says package. | |
| Content catalog | The signed, versioned content packs an installation or an organization installs, pins and rolls back. | Content catalog | Danh mục nội dung | `/api/v1/content` | | `pkg/domain/contentcatalog` | | |
| Rule source | A repository the platform pulls scanner rules or templates from. | Rule source | Nguồn quy tắc | `/api/v1/content-sources` | | `pkg/domain/contentsource` | Module id `template_sources`, audit `content_source.*` and `template_source.*`. | template source |
| CI pipeline | A customer's CI pipeline that reports to OpenCTEM. The only meaning of "pipeline". | CI pipeline | Pipeline CI | `/api/v1/ci/pipelines` | `ci_pipelines` | `pkg/domain/cirun` | | |
| CI run | One CI pipeline execution reporting to OpenCTEM. | CI run | Lần chạy CI | `/api/v1/ci/runs` | `ci_runs` | `pkg/domain/cirun` | | |

## Sensors

| Term | Meaning | Console (en) | Console (vi) | API | Database | Code | Still differs | Retired names |
|---|---|---|---|---|---|---|---|---|
| Sensor | Software that connects out to the platform with its own key, claims commands and reports results. | Sensor | Sensor | `/api/v1/sensors`, sensor plane `/api/v2/sensor`, `/api/v3/sensor` | `sensors` | `pkg/domain/sensor`, sdk-go | | agent (for a sensor) |
| Sensor role | What a sensor does: **scanner** (assesses other hosts), **collector** (pushes data from systems inside the network), **ai-worker** (runs AI agents), **endpoint** (planned: reports about its own host). | Scanner, Collector, AI worker, Endpoint | Trình quét, Collector, AI worker, Endpoint | | `sensors.type` (`worker`, `collector`, `sensor`) | `sensor.SensorType` | No role field yet; the stored type values do not match the roles. | agent (for the endpoint role) |
| Organization sensor | A sensor an organization runs in its own networks. | Organization sensor | Sensor của tổ chức | `/api/v1/sensors` | `sensors.scope = 'organization'` | | | |
| Shared sensor | A sensor the operator runs for every organization, for public targets. | Shared sensor | Sensor dùng chung | `/api/v1/admin/shared-sensors` | `sensors.scope = 'instance'` | | Also called platform sensor and instance in some admin routes, settings and columns. | platform sensor (in text) |
| Sensor key | A sensor's credential, `octs_...`. | Sensor key | Khóa sensor | | `sensor_api_keys` | | | agent key |
| Pairing code | A short code that binds a new sensor to an organization. | Pairing code | Mã ghép nối | `/api/v1/sensor-pairings` | | | | |
| Tool contract | How any tool, ours or a third party's, plugs into a sensor: a `tool.yaml` manifest (`openctem.io/tool/v1`) and the adapter protocol. | Tool | Công cụ | | | sdk-go `pkg/tool` | | plugin, wrapper |
| Tool pack | A signed archive that distributes one or more tools (`openctem.io/pack/v1`). | Tool pack | Gói công cụ | | | sdk-go `pkg/tool/pack` | | |

## AI

| Term | Meaning | Console (en) | Console (vi) | API | Database | Code | Still differs | Retired names |
|---|---|---|---|---|---|---|---|---|
| AI agent | An AI principal that works on an organization's data under its own identity, with accountable owners and a role: analyst, remediator, reporter, hunter or router. Always "AI agent", never a bare "agent". | AI agent | AI agent | `ai_agent` | `actor_kind = ai_agent` | `aiagent`, `AIAgent` | Open work in progress names the table and routes after "analyst"; it follows this row before it merges. | AI analyst (as the principal's name), agent |
| Playbook | A procedure an AI agent follows (`openctem.io/playbook/v1`), built and tested with `openctem playbook init` and `openctem playbook test`. | Playbook | Playbook | | | sdk-go `pkg/harness/playbook` | | |
| AI worker | The sensor role, and the `openctemio/ai-worker` program, that runs AI agents. | AI worker | AI worker | | | `ai-worker` | | analyst (as the worker or role name) |
| Harness | The sdk-go library that runs an AI agent's tool loop. Code only. | | | | | sdk-go `pkg/harness` | | `pkg/analyst` |
| AI assistant (MCP) | An external AI application that connects to the MCP server as the person who approved it. Not an AI agent. | AI assistant (MCP) | Trợ lý AI (MCP) | `/api/v1/mcp` | | `internal/app/mcp` | | |

## Words with one meaning only

- **agent**: only in "AI agent" and "User-Agent". It is not a sensor.
- **pipeline**: only a customer's CI pipeline.
- **workflow**: only "scan workflow". An event rule is an automation.
- **job**: not used in text a person reads; use task (scan work) or command (any sensor instruction).
- **tenant**: internal (database, Go). Text a person reads says organization.
- **team**: a group of members inside an organization, never the organization.
- **exception**: not used for suppression rules.
