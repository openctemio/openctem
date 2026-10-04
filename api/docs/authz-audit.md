# Rà soát & chuẩn hóa phân quyền — OpenCTEM

> **Trạng thái (cập nhật 2026-10-04):** ảnh chụp lịch sử của đợt rà soát 2026-09.
> Phần lớn phát hiện đã được sửa hoặc đã chốt chính sách — xem **§8** (trạng thái
> trên `develop`). Mô hình hiện hành (canonical):
> [architecture/authorization-matrix.md](architecture/authorization-matrix.md).
> Nội dung §1–§7 giữ nguyên như lúc rà soát (đường dẫn `ui/…` nay là `web/…`;
> số liệu như 159 quyền, ~878 route là của thời điểm đó).
> **Phạm vi:** khi rà soát là repo `api` + `ui`; nay là monorepo `openctemio/openctem` (`api/` + `web/`).
> **Phương pháp:** review với tư duy tấn công — giả định kẻ tấn công gọi API trực tiếp, sửa mọi tham số client.
> **Ngày:** 2026-09.

---

## 1. Tóm tắt hiện trạng kiến trúc phân quyền

**Kết luận nhanh:** hệ thống **KHÔNG có lỗ hổng cross-tenant Critical/High** đang tồn tại. Cách ly giữa các loại principal (user JWT / platform-admin / agent API-key / MCP / SCIM) sạch; tenant luôn lấy từ identity đã xác thực, không tin body. Vấn đề thực là **nhập nhằng thiết kế + một escalation nội-tenant (AUTHZ-01) + thiếu lưới an toàn tự động (AUTHZ-02)**.

**Backend quyết định duy nhất — ĐÚNG.** Frontend chỉ UX: `proxy.ts` không làm authz, mọi call dữ liệu đi qua Next proxy `/api/v1/[...path]` forward token httpOnly của chính user; backend re-check mọi request.

**Router & so khớp quyền — AN TOÀN.** Router bọc go-chi (`internal/infra/http/chi_router.go:33-34`) mount `CleanPath` + `StripSlashes` → chuẩn hóa `//`, trailing-slash, dot-segment trước khi route. Quyết định quyền đọc từ **context JWT/API-key**, KHÔNG so chuỗi `r.URL.Path` → **không có bypass qua trailing-slash/hoa-thường/encode**.

**Thứ tự middleware (`routes.go:874-901`):** auth → userSync → SSO-enforce → RequireTenant → active-membership → **permission-sync** → CSRF → rate-limit → per-route `Require(perm)`. Authz chạy sau auth, áp cho mọi group. `IsAdmin` (owner/admin) short-circuit `HasPermission` = true (bypass admin có chủ đích).

**Có 5 cơ chế gate chồng nhau — đây là nguồn "nhập nhằng":**
1. **RBAC permission** `Require(perm)` — fail-closed, admin bypass toàn bộ.
2. **Team-role** `RequireTeamAdmin/Owner` — đọc membership DB sống, gate `/tenants/{tenant}/*`.
3. **Module gate** `RequireModule` — **fail-OPEN, KHÔNG admin bypass**, feature-flag (không phải security boundary).
4. **Data-scope** `user_accessible_assets` — chỉ assets+findings, non-admin, fail-open.
5. **RLS** — ~99 policy, **0 bảng bật + middleware chưa nối = vô hiệu** (cố ý, shadow mode).

**Tính quyền hiệu lực, cache, thu hồi — PHẦN LỚN ĐÚNG:**
- Cache invalidate **sau** DB write, bump version per-user (Redis INCR), xử lý role-đổi-ảnh-hưởng-nhiều-user, TTL 5 phút (`permission_cache.go:29`) + version 30 ngày.
- Stale-permission: JWT `pv` vs Redis version; mismatch + method ghi → **HTTP 409** (chặn write), và **override permission tươi** vào context mọi request (`permission_sync.go:123-154`). → **thu hồi có hiệu lực ở request kế tiếp cho write**. Wired live (`cmd/server/services.go:1471-1493`, `routes.go:312-313`).
- `RevokeAllSessions` cho offboarding, 0-second window (`auth/session.go:171-193`). SQL tham số hóa toàn bộ.
- **Mã quyền zero-drift:** Go 159 ≡ DB seed 159 ≡ UI 159 (khác biệt = ∅ hai chiều).

**Điểm yếu hệ thống:**
- **Không có test tự động phát hiện route chưa map quyền** (AUTHZ-02) — nguyên tắc "fail-closed cho route chưa khai báo" không được máy enforce.
- JWT vẫn nhúng cả mảng permission (đã được sync middleware ghi đè, nhưng nên hoàn tất slim-token).
- Hai mô hình enforcement song song (permission vs team-role) + quyền tinh không enforce → ma trận quyền nói dối.

---

## 2. Bảng endpoint (Giai đoạn 0) — tổng hợp theo nhóm

> Tổng ~878 route. Mọi group mặc định mang `buildTokenTenantMiddlewares` (auth + RequireTenant + membership + permission-sync + CSRF + rate-limit) trừ khi ghi chú. "module gate" = `RequireModule` (fail-open). Dưới đây là bản tóm tắt theo file route + **đánh dấu endpoint có vấn đề**; danh sách route đầy đủ đã được duyệt qua router.

| Route file / nhóm | Quyền chính | Ghi chú / vấn đề |
|---|---|---|
| `auth.go` — /auth, /users/me, /settings/* | public (auth flow) · auth-only (self) · `RequireAdmin` (saml/idp/verified-domains) | OK. `/users/me*` self-scoped. |
| `tenant.go` — /tenants, /invitations | base-auth · `RequireMembership` · `RequireTeamAdmin` · `RequireTeamOwner` | `GET /tenants/` scoped `ListUserTenants(userID)` ✓. **Team-role gate ≠ permission gate → AUTHZ-04.** |
| `assets.go` — assets/components/scope/... | Assets/Components/Scope/AssetGroups Read/Write/Delete | OK; list scoped theo tenant + data-scope. |
| `asset_dedup.go` | AssetsWrite/Delete/Read | OK (prior IDOR đã fix). |
| `exposure.go` — exposures/threat-intel/credentials/vulnerabilities/findings | Findings/Vulnerabilities/Credentials Read/Write/Delete + FindingsFixApply/Verify/Approve | **AUTHZ-05** (quyền finding tinh không enforce), **AUTHZ-06** (`GET /findings/ai-triage/config` thiếu gate, :408), **AUTHZ-07** (credentials plaintext). `POST /agent/credentials/ingest` agent-key (by design). `/threat-intel`,`/vulnerabilities` base-chain global-catalog. |
| `validation.go` | FindingsRead/Write · `/validation/evidence` agent-key | OK (agent-key by design). |
| `scanning.go` — commands/agents/scans/... (~110 route) | Commands/Agents/Scans/Tools/... Read/Write/Delete + module gate | **`/agent/*` 25 route: API-key, KHÔNG RBAC — by design** (tenant từ key). |
| `misc.go` — dashboard/audit/sla/integrations/notifications/webhooks | Dashboard/Audit/SLA/Integrations/... + `RequireAdmin` (audit verify/rebaseline) | `/notifications/*` tenant+user-scoped in-handler ✓. Jira webhook HMAC. |
| `access_control.go` — groups/roles/permission-sets/assignment-rules | Groups/Roles/PermissionSets/AssignmentRules + `RequireOwner` (destructive) | **AUTHZ-01** (role create+assign escalation). `DeleteRole` KHÔNG owner-gate (khác sibling) — AUTHZ-13-liên quan. |
| `ctem.go` — compensating-controls/attacker-profiles/threat-models/... | CTEM domain perms + module gate | OK. |
| `admin.go` — /api/v1/admin/* | **AdminAuthMiddleware (API-key, KHÔNG JWT)** · RequireRole super_admin/ops_admin | Realm tách biệt ✓ (mô hình 3-plane kiểu Tenable). |
| `pentest.go` | Pentest* + per-campaign role | module gate. OK. |
| `scim.go` | SCIMAuth (per-tenant bearer) · `/scim-tokens` RequireAdmin | OK. |
| `compliance/ctemid/ioc/simulation/threat_actor/remediation/business_unit/reports` | domain perms + module gate | OK. |

**Cửa vào ngoài HTTP-JWT (đều kiểm soát):** `/metrics` (bearer, fail-closed 404), `/agent/*` (API-key), `/scim/v2` (bearer), `/api/v1/mcp` (`oct_` key + IP rate-limit), `/ws` (ticket/JWT), Jira/GitHub webhook (HMAC per-tenant). **Không có pprof/expvar/debug endpoint.**

---

## 3. Danh sách phát hiện

### AUTHZ-01 · **HIGH** · Leo thang đặc quyền qua tạo+gán role (thiếu "trần đặc quyền")
- **Vị trí:** `internal/app/accesscontrol/role.go:206-214` (CreateRole), `:362-378` (UpdateRole), `:578-638` (AssignRole), `:600-603` (chỉ chặn tenant-mismatch, KHÔNG loại system role).
- **Mô tả:** `CreateRole/UpdateRole` nhận `Permissions []string` tùy ý, chỉ validate mã tồn tại trong catalogue — **không kiểm tra người tạo có sở hữu các quyền đó không**. `AssignRole` không chặn self-assign và **không loại system role `owner`/`admin`** (tenant_id NULL).
- **Cách khai thác:** một principal có custom role chứa `team:roles:write` + `team:roles:assign` (nhưng KHÔNG phải admin):
  1. `POST /api/v1/roles` tạo role chứa `settings:billing:write`, `scans:secret_store:read`, … (bất kỳ trong 159 mã).
  2. `POST /api/v1/users/{myId}/roles` tự gán role đó → **có mọi quyền nghiệp vụ**.
  - Biến thể nặng: gán thẳng system role `owner` (đủ 159 quyền granular). (Lưu ý: cờ owner/admin-bypass lấy từ `tenant_members` nên có thể không lật, nhưng permission-set thì đủ.)
- **Đề xuất sửa:** (a) trong Create/Update role, từ chối mọi permission mà effective-set của caller không có (owner/full-access miễn); (b) trong Assign/Set/Bulk, từ chối gán role có tập quyền vượt caller + **chặn gán system `owner`/`admin` trừ owner**; (c) cân nhắc cấm self-assign role tăng quyền.
- **Ảnh hưởng khi sửa:** chỉ ảnh hưởng tenant có custom role cấp `roles:write`+`roles:assign` cho non-admin (hiếm). Owner/admin không bị ảnh hưởng.

### AUTHZ-02 · **MEDIUM (process)** · Không có test phát hiện route chưa map quyền
- **Vị trí:** toàn bộ `internal/infra/http/routes/` — chỉ có baseline *doc-coverage* (`api/openapi/undocumented-routes.txt`, 439/878 route chưa annotate); **không có test walk router đối chiếu quyền**.
- **Mô tả:** route ship thiếu `Require(...)` sẽ KHÔNG fail CI. Vi phạm nguyên tắc "fail-closed cho route chưa khai báo" ở mức máy-móc.
- **Khai thác:** không trực tiếp; là rủi ro hồi quy — một PR tương lai quên gate là lỗ hổng thầm lặng.
- **Đề xuất sửa:** thêm test `chi.Walk()` assert mọi route (trừ allowlist public tường minh) mang middleware auth+permission. Đóng vĩnh viễn cả lớp "route hở".
- **Ảnh hưởng:** không ảnh hưởng người dùng; chỉ thêm gate CI.

### AUTHZ-03 · **MEDIUM** · Permission-set "deny" KHÔNG chặn API
- **Vị trí:** gate thật `unified_auth.go:370-388` → `role_repository.go:611-635` (UNION role_permissions, không allow/deny). Resolver deny-aware `pkg/domain/accesscontrol/resolver.go:147-159,172-191` chỉ phục vụ `/me/permissions` + group mgmt (Layer-2).
- **Mô tả:** công thức `(role ∪ granted) − denied` (deny-wins) **có tồn tại nhưng không phải cổng gate HTTP**. Một "deny" trong permission-set **không** chặn API call. Thêm nữa deny **không thắng xuyên group** (`ResolveUserPermissions` union từng group đã resolve → deny group A bị group B allow gỡ).
- **Khai thác:** operator tạo permission-set deny `findings:delete` cho user, tưởng đã chặn — user vẫn gọi `DELETE /findings/{id}` thành công nếu role có `findings:delete`.
- **Đề xuất sửa:** chốt ý đồ (xem Câu hỏi Q1). Nếu deny phải gate API → cho `Require()` resolve qua resolver deny-aware, và áp deny **sau** union xuyên group. Nếu chỉ là data-scope Layer-2 → ghi rõ + UI ngừng trình bày "deny" như một access control.
- **Ảnh hưởng:** tùy quyết định; nếu bật deny-gate có thể chặn bớt hành vi đang cho phép.

### AUTHZ-04 · **MEDIUM** · Hai mô hình enforcement song song; hằng quyền team/billing/members inert
- **Vị trí:** `unified_auth.go` (Require/RequireAdmin — JWT flag) vs `middleware/tenant.go:187-246` (RequireTeamAdmin/Owner — DB membership). Hằng `permission.Members*/Team*/Billing*/Settings*` không được route nào tham chiếu.
- **Mô tả:** cùng tầng cấp quyền, hai cơ chế rời. `/tenants/{tenant}/*` gate bằng **role** (RequireTeamAdmin), không phải permission → cấp custom role quyền `team:members:write` vẫn KHÔNG quản lý được member. Hai "oracle admin" (JWT `IsAdmin` đóng băng lúc mint vs membership DB sống) có thể mâu thuẫn sau khi đổi role chưa refresh token.
- **Khai thác:** không phải breach; là bẫy nhận thức + hằng quyền chết.
- **Đề xuất sửa:** chốt MỘT mô hình cho ranh giới admin/owner tenant (khuyến nghị live-membership), retire biến thể JWT-flag hoặc ghi rõ. Xem Q4.
- **Ảnh hưởng:** cần rà route dùng `RequireAdmin`/`RequireOwner` (JWT) chuyển sang membership — phải test kỹ owner/admin không bị khóa.

### AUTHZ-05 · **MEDIUM** · Quyền finding tinh được định nghĩa + gán role nhưng không enforce
- **Vị trí:** `internal/infra/http/routes/exposure.go` — `/{id}/assign`, `/{id}/triage`, `/{id}/status`, `/bulk/assign`, `/bulk/status` đều `Require(FindingsWrite)` thay vì `FindingsAssign/Triage/Status/BulkUpdate` (các mã này CÓ trong role-map).
- **Mô tả:** role **member** cố ý KHÔNG được cấp `FindingsAssign/BulkUpdate` nhưng vẫn assign/bulk được vì route chỉ đòi `FindingsWrite`. **Ma trận quyền nói dối.**
- **Khai thác:** member gọi `POST /findings/{id}/assign` thành công dù ma trận nói không.
- **Đề xuất sửa:** wire các mã tinh vào route tương ứng, HOẶC xóa mã + role-map cho khớp thực tế. Thêm CI test module↔permission.
- **Ảnh hưởng:** nếu enforce, member mất khả năng assign/bulk (đúng ý đồ role) — cần thông báo.
- **Liên quan (ĐÃ FIX):** bug SoD ở `/findings/{id}/verify` (dùng `FindingsWrite` thay `FindingsVerify`) đã sửa ở **PR api#505**.

### AUTHZ-06 · **LOW** · `GET /findings/ai-triage/config` thiếu gate quyền
- **Vị trí:** `internal/infra/http/routes/exposure.go:408`.
- **Mô tả:** nằm trong group findings mà mọi sibling có `Require(Findings*)`, riêng route này không có → mọi member đọc được cấu hình AI-triage (provider/model/mode).
- **Khai thác:** `GET /api/v1/findings/ai-triage/config` bởi member không quyền findings.
- **Đề xuất sửa:** thêm `middleware.Require(permission.FindingsRead)`.
- **Ảnh hưởng:** không đáng kể.

### AUTHZ-07 · **LOW (by-design, cần quyết)** · Lộ plaintext credential trong tenant
- **Vị trí:** `internal/app/.../credential_import.go:597,605,732` — `GET /credentials`, `/credentials/{id}`, `/credentials/{id}/related`, `/credentials/identities/{identity}/exposures` trả `secret_value` plaintext.
- **Mô tả:** tenant-scoped (không cross-tenant), nhưng **bất kỳ user có `credentials:read`** kéo được toàn bộ secret bị lộ, không có field-gate hay audit-per-access.
- **Đề xuất sửa:** gate bằng quyền cao hơn + ghi audit mỗi lần đọc secret_value. Xem Q3.
- **Ảnh hưởng:** thu hẹp ai xem được plaintext.

### AUTHZ-08 · **LOW** · `is_active=false` của permission không enforce lúc gate
- **Vị trí:** `role_repository.go:611-635` (GetUserPermissions không join `is_active`); trái với `permission_repository.go:175` (ValidatePermissions có filter).
- **Mô tả:** vô hiệu hóa 1 permission trong catalogue chỉ chặn cấp mới; `role_permissions` cũ vẫn cấp. Hiện chưa có code path deactivate nên latent.
- **Đề xuất sửa:** join `permissions p ON p.id=rp.permission_id AND p.is_active` trong GetUserPermissions.
- **Ảnh hưởng:** không, cho tới khi có tính năng deactivate.

### AUTHZ-09 · **LOW** · JWT nhúng cả mảng permission (đã giảm thiểu)
- **Vị trí:** `pkg/jwt/jwt.go:60,479,491,566`; `unified_auth.go:173,383-385`.
- **Mô tả:** token mang `Permissions []string`. Đã được `EnrichPermissions` ghi đè bằng permission tươi mỗi request tenant-scoped (AUTHZ giảm thiểu), nhưng vẫn là fallback nếu một chain tương lai thiếu sync middleware.
- **Đề xuất sửa:** hoàn tất slim-token — ngừng nhúng `Permissions` cho non-admin, bỏ fallback `claims.HasPermission`.
- **Ảnh hưởng:** không (chỉ dọn dẹp), nhưng cần đảm bảo mọi chain có sync middleware.

### AUTHZ-10 · **LOW (latent hardening)** · Repo Update/Delete `WHERE id=$1` thiếu tenant scope
- **Vị trí:** `scan_repository.go:264,313`, scan-session `:205`, `integration_repository.go:106,226`, `asset_group_repository.go:161`, scan-profile Update/Delete. An toàn hiện tại chỉ vì caller pre-verify tenant.
- **Mô tả:** cách ly tenant dựa convention, không cấu trúc. Dễ vỡ khi có call-site mới quên check.
- **Đề xuất sửa:** thêm `AND tenant_id=$N` (như `scanner_template_repository.go:262` đã làm).
- **Ảnh hưởng:** không (chỉ tăng phòng thủ).

### AUTHZ-11 · **LOW (frontend hardening)** · Trang nhạy cảm chỉ guard client-side
- **Vị trí:** `ui/src/app/(dashboard)/layout.tsx:14-74` (không redirect/notFound server-side), `ui/src/components/route-guard.tsx:26` (client).
- **Mô tả:** trang gated (settings/audit, billing, users) guard bằng client `RouteGuard`; route vẫn mount rồi hiện "Access Denied". An toàn vì data fetch client-side → backend 403, nhưng nên guard server-side cho route nhạy cảm.
- **Đề xuất sửa:** thêm server-component guard (đọc cookie token → gọi `/me/permissions` → redirect/notFound) cho `/settings/{audit,billing,users}`.
- **Ảnh hưởng:** không (chỉ hardening + UX).

### AUTHZ-12 · **LOW (frontend)** · Dead-code footgun
- **Vị trí:** `ui/src/lib/cache.ts:126-161` (`createCachedApiClient` — cache global không auth header, bẫy cross-user), `ui/src/lib/cookies-server.ts:199-210` (`setCsrfToken` — cờ sai, phá double-submit). Đều 0 caller. Thiếu `import 'server-only'` ở module token/env.
- **Đề xuất sửa:** xóa 2 hàm dead + thêm `import 'server-only'` vào `cookies-server.ts`/`env.ts`.
- **Ảnh hưởng:** không.

### AUTHZ-13 · **LOW** · `UpdateMemberRole` thiếu self-guard; `DeleteRole` không owner-gate
- **Vị trí:** `internal/app/tenant/service.go:580-628` (chặn đụng owner + promote-to-owner, nhưng không chặn admin sửa membership chính mình); `access_control.go:195` (`DeleteRole` chỉ `RolesDelete`, khác sibling group/rule/permission-set có `RequireOwner`).
- **Mô tả:** owner path đã an toàn; hai điểm bất đối xứng nhỏ. `DeleteRole` sửa kiểu nào là **quyết định chính sách** (admin có `RolesDelete` — thêm owner-gate sẽ tạo mâu thuẫn permission-vs-gate). Xem Q7.
- **Ảnh hưởng:** tùy quyết định.

### AUTHZ-14 · **LOW** · `IsOwner`/`RequireOwner` không tin cậy dưới OIDC
- **Vị trí:** `unified_auth.go:478-481` đọc `RoleKey`; OIDC set `RoleKey` = realm role (`:207`), không phải tenant role.
- **Mô tả:** các delete owner-only trong `access_control.go` lệch nếu đăng nhập OIDC.
- **Đề xuất sửa:** `IsOwner` resolve tenant role thật (không lấy realm primary role), hoặc ghi rõ owner-gating chỉ hỗ trợ local-auth.
- **Ảnh hưởng:** ảnh hưởng tenant dùng OIDC + owner-only ops.

### AUTHZ-15 · **INFO** · Code chết tạo ranh giới giả + doc lỗi thời
- **Vị trí:** `unified_auth.go:41-43,500-544` (`RequirePlatformAdmin`/realm role `platform_admin` — chưa mount; ranh giới platform THẬT = AdminUser + X-Admin-API-Key), `auth.go:158-217` (`RequireTenantRole/RequireMinTenantRole` inert), `jwt.go:632` (`GenerateSlimAccessToken` 0 caller). `api/CLAUDE.md` ghi sai "Module … no route gating in OSS" (thực tế 26 group gated) và "JWT chỉ chứa perm_version" (thực tế mang cả mảng).
- **Đề xuất sửa:** xóa code chết + sửa 2 câu doc.

### AUTHZ-16 · **INFO** · Không có `expires_at`/`is_active` trên grant (feature gap)
- **Vị trí:** `migrations/000006_roles.up.sql:30-51` (`user_roles`/`role_permissions` không có cột expiry/is_active); `GroupPermission` chỉ có `effect`.
- **Mô tả:** không hỗ trợ cấp quyền tạm thời/time-boxed. Checklist "expiry honored kể cả trong cache" → **Không áp dụng** (không có cột để honor). Xem Q5.

### AUTHZ-17 · **INFO** · 3 danh sách mã quyền đồng bộ chỉ nhờ kỷ luật
- **Vị trí:** `pkg/domain/permission/permission.go` (Go), 6 migration seed, `ui/src/lib/permissions/constants.ts` (TS). **Hiện zero-drift (159≡159≡159).**
- **Đề xuất sửa:** codegen từ một nguồn + CI test set-equality, hoặc startup reconciler upsert `AllPermissions()`.

### Ghi nhận by-design (không phải bug)
- **RLS shadow mode** — ~99 policy, 0 bảng bật, middleware chưa nối. Cố ý (xem migration header). **Nhưng KHÔNG phải backstop** — cách ly tenant hiện chỉ dựa `WHERE tenant_id` viết tay. Nếu muốn defense-in-depth thật thì phải bật (có thứ tự rollout) hoặc gỡ scaffolding + ngừng ngụ ý.
- **`/agent/*`, `/validation/evidence`, `/agent/credentials/ingest`** — API-key auth, không RBAC, tenant từ key. Đúng thiết kế agent-plane.

---

## 4. Đối chiếu checklist

| Mục | Kết quả |
|---|---|
| **A. Độ phủ & cơ chế** | Route chưa khai báo: chỉ self-scoped/agent-key hợp lệ (trừ AUTHZ-06). **Thiếu test coverage (AUTHZ-02).** So khớp theo pattern router ✓. Middleware sau auth, mọi sub-router ✓. Lỗi đọc quyền → từ chối ✓ (fail-closed 409/deny). Cửa vào khác đều kiểm soát ✓. Không pprof/debug ✓. |
| **B. Object-level & data** | BOLA/IDOR: **CLEAN** (tenant-scoped SQL hoặc fetch-then-check + data-scope). List/export scope query-level ✓. Mass-assignment: **không** (tenant/role luôn overwrite từ context). Response redaction ✓ (`sanitizeConfigMap`). Không tin client identity ✓. Điểm cần quyết: AUTHZ-07 (plaintext credential). |
| **C. Quyền hiệu lực/cache/thu hồi** | Công thức deny-wins **có nhưng không phải gate API** (AUTHZ-03). is_active không enforce (AUTHZ-08). expires_at **Không áp dụng** (AUTHZ-16). Token mang permission list (AUTHZ-09, đã giảm thiểu). Invalidate sau commit + version + many-user + TTL ✓. Revoke-all-sessions ✓. SQL tham số hóa ✓. |
| **D. Quản trị phân quyền** | Admin ops gate bằng `team:*` riêng + RequireOwner ✓ (AUTHZ-01 là ngoại lệ — thiếu trần đặc quyền). Self-grant: **có lỗ (AUTHZ-01)**. Mapping endpoint→quyền là compile-time (**Không áp dụng** runtime-edit). Audit grant/revoke before/after ✓ (AUTHZ-15 doc). |
| **E. Frontend Next.js** | CVE-2025-29927 **đã vá** (16.3.3). proxy UX-only ✓. Server Actions chỉ auth-flow qua backend ✓. Route Handler forward user token, từ chối `x-tenant-id` ✓. Không cache cross-user (AUTHZ-12 dead-code trap). Token httpOnly cookie ✓. Nút gate theo permission code ✓. 403/perm-version sync ✓. Hardening: AUTHZ-11, AUTHZ-12. |
| **F. Nhất quán mã quyền** | **Zero-drift 159≡159≡159** ✓. Chưa có cơ chế giữ đồng bộ tự động (AUTHZ-17). |

---

## 5. Câu hỏi nghiệp vụ cần bạn trả lời (Giai đoạn 2 phụ thuộc)

- **Q1 (AUTHZ-03):** Permission-set "deny" có ý định **chặn API** không, hay chỉ là data-scope Layer-2? (quyết định có phải đưa deny-resolver vào cổng gate.)
- **Q2 (AUTHZ-01):** Có áp "trần đặc quyền" (không cấp/gán được quyền mà bản thân không có) + chặn gán system role owner/admin (chỉ owner mới gán) không? (Khuyến nghị: CÓ.)
- **Q3 (AUTHZ-07):** `credentials:read` có được xem **plaintext** secret bị lộ không, hay phải gate bằng quyền cao hơn + audit mỗi lần đọc?
- **Q4 (AUTHZ-04):** Thống nhất ranh giới admin/owner tenant về **một** mô hình (live-membership) — retire biến thể JWT-flag? Hay giữ team-role cho team-ops và permission cho nghiệp vụ (ghi rõ ranh giới)?
- **Q5 (AUTHZ-16):** Có cần cấp quyền **tạm thời/time-boxed** (`expires_at`) và **per-user grant/deny** không? (Hiện data model chưa có.)
- **Q6 (maker-checker):** Quy tắc "người tạo không tự duyệt" / "chỉ xem dữ liệu chi nhánh mình" áp cho **luồng nào** cụ thể? (Bạn nêu như ví dụ — cần chỉ rõ flow để đưa vào policy function dùng chung.)
- **Q7 (AUTHZ-13):** Admin (không phải owner) có được **xóa role** không? (Quyết định owner-gate `DeleteRole` hay bỏ owner-gate ở siblings.)

---

## 6. Bảng ưu tiên (cho Giai đoạn 2)

| Mã | Mức | Một dòng | Cần migration? | Ảnh hưởng người dùng | Cần phối hợp BE/FE? |
|---|---|---|---|---|---|
| AUTHZ-01 | **High** | Trần đặc quyền role create/assign | Không | Chỉ tenant dùng custom role hiếm | BE |
| AUTHZ-02 | Medium | Test coverage route→quyền | Không | Không | BE (CI) |
| AUTHZ-03 | Medium | Deny-resolver vào gate API | Có thể | Có (nếu bật deny) | BE (+FE nhãn) |
| AUTHZ-04 | Medium | Hợp nhất admin/owner model | Không | Cần test owner/admin | BE |
| AUTHZ-05 | Medium | Enforce quyền finding tinh | Không | Member mất assign/bulk | BE (+FE nút) |
| AUTHZ-06 | Low | Gate ai-triage/config | Không | Không | BE |
| AUTHZ-07 | Low | Gate+audit plaintext credential | Không | Thu hẹp người xem | BE (+Q3) |
| AUTHZ-08 | Low | is_active enforce | Không | Không (latent) | BE |
| AUTHZ-09 | Low | Slim-token | Không | Không | BE |
| AUTHZ-10 | Low | tenant scope repo Update/Delete | Không | Không | BE |
| AUTHZ-11 | Low | Server guard trang nhạy cảm | Không | Không | FE |
| AUTHZ-12 | Low | Xóa dead-code FE + server-only | Không | Không | FE |
| AUTHZ-13 | Low | self-guard + DeleteRole owner | Không | Tùy Q7 | BE |
| AUTHZ-14 | Low | IsOwner OIDC | Không | Tenant OIDC | BE |
| AUTHZ-15 | Info | Xóa code chết + sửa doc | Không | Không | BE |
| AUTHZ-16 | Info | expires_at/per-user grant | **Có** | Tính năng mới | BE (+Q5) |
| AUTHZ-17 | Info | Codegen + CI mã quyền | Không | Không | BE+FE |

---

> **DỪNG Ở GIAI ĐOẠN 1.** Chờ bạn duyệt danh sách phát hiện + trả lời câu hỏi nghiệp vụ (mục 5) trước khi tôi lập kế hoạch sửa (Giai đoạn 2). Ghi chú: bug SoD `/findings/{id}/verify` đã fix ở PR api#505 (phát hiện ở đợt review trước, cùng lớp AUTHZ-05).

---

## 7. Trạng thái thực hiện — Giai đoạn 3 (đợt 1: hạng mục không phụ thuộc chính sách)

> Làm theo yêu cầu "làm được gì thì làm cho xong trước". Tất cả commit **local, CHƯA push** (rule 6). Mỗi hạng mục: verify-first → sửa → build/test → local commit.

| Mã | Trạng thái | Ghi chú |
|---|---|---|
| **AUTHZ-01** | ✅ **Đã sửa** | Verify-first phát hiện handler đã có `assertCanGrantPermissions` cho Create/Update/Assign/SetUserRoles + có sẵn `role_escalation_test.go`. Path DUY NHẤT còn hở: `BulkAssignRoleMembers` — đã thêm guard + mở rộng test. (commit local `887aa07`) |
| **AUTHZ-06** | ✅ **Đã sửa** | Thêm `Require(FindingsRead)` cho `GET /findings/ai-triage/config`. (commit local `b3b6823`) |
| **AUTHZ-15** | ✅ **Đã sửa (phần doc)** | Sửa 2 câu sai trong `api/CLAUDE.md` (module gating IS live; JWT mang cả mảng perm). Xóa dead middleware code (RequirePlatformAdmin…) để Phase 3 (cleanup, không phải security). (commit local `b3b6823`) |
| **AUTHZ-12** | ✅ **Đã sửa (phần dead-code)** | Xóa `ui/src/lib/cache.ts` (footgun cross-user cache, 0 import) + `setCsrfToken/generateCsrfToken` (0 caller). `import 'server-only'` **defer** (package chưa cài — cần thêm dependency). (commit local `159016e`) |
| **AUTHZ-02** | ⏳ **Defer (có lý do)** | Cần harness walk-router dựng full route tree (mọi handler-dep) — task riêng, không half-do fragile. AUTHZ-06 đã xóa offender duy nhất nó sẽ bắt. |
| **AUTHZ-08** | ⏳ **Defer (có lý do)** | Chạm hot auth-query `GetUserPermissions` + không có repo-test-DB harness → không đổi query enforce khi chưa test được (rule 4). An toàn hôm nay (mọi perm `is_active=true`). |
| AUTHZ-03,04,05,07,10,11,13,14,16,17 | ⏸ **Chờ duyệt** | Phụ thuộc quyết định chính sách (Q1–Q7) — thuộc Giai đoạn 2/3 sau khi bạn duyệt. |

**Đợt 1 kết quả:** 1 lỗ hổng escalation thật (bulk-assign) đã đóng + test; 1 route hở đã gate; footgun frontend + doc sai đã dọn. Đều verify build/test/lint, commit local, **chưa push** — chờ bạn ra lệnh push.

---

## 8. Trạng thái trên `develop` (kiểm tra 2026-10-04)

Số PR là của `openctemio/openctem` (repo `api` cũ đã đổi tên). Các commit
"local" ở §7 đã được merge qua các PR dưới đây.

| Mã | Trạng thái | Bằng chứng |
|---|---|---|
| AUTHZ-01 | ✅ Đã sửa (#506) | `api/internal/app/accesscontrol/grant_guard.go` |
| AUTHZ-02 | ✅ Đã sửa (#512) | `api/tests/unit/route_authz_coverage_test.go` |
| AUTHZ-03 | Đã chốt: không xây deny-gate (allow-only) | authorization-matrix.md, "Settled model" |
| AUTHZ-04 | Hoãn có chủ ý | authorization-matrix.md, "Known, deliberate gaps" |
| AUTHZ-05 | ✅ Đã sửa (#516) | `routes/exposure.go` dùng `FindingsBulkUpdate/Status/Assign/Triage/Verify` |
| AUTHZ-06 | ✅ Đã sửa (#507) | `GET /api/v1/findings/ai-triage/config` có `Require(FindingsRead)` |
| AUTHZ-07 | ✅ Đã sửa (#514, #591) | đọc thì che (mask), mã hóa khi lưu, `reveal` cần quyền riêng và được audit |
| AUTHZ-08 | ✅ Đã sửa (#515) | `postgres/role_repository.go` join `p.is_active = TRUE` |
| AUTHZ-09 | Còn mở | `pkg/jwt/jwt.go` vẫn nhúng `Permissions` (được `EnrichPermissions` làm mới mỗi request) |
| AUTHZ-10 | Sửa một phần (#511) | `ScanRepository.Update` đã scope tenant; `Delete` vẫn chỉ `WHERE id = $1`; các repo khác chưa rà lại |
| AUTHZ-11 | Còn mở | |
| AUTHZ-12 | Đã xóa dead code (openctemio/ui#450) | `server-only` vẫn chưa được import |
| AUTHZ-13 | Một phần: `DeleteRole` có trần đặc quyền ở service (quyết định 2026-10-02) | self-guard của `UpdateMemberRole` chưa kiểm lại |
| AUTHZ-14 | Còn mở / hoãn | |
| AUTHZ-15 | Một phần | `RequirePlatformAdmin` đã xóa; `GenerateSlimAccessToken` vẫn còn (không dùng) |
| AUTHZ-16 | Đã chốt: không làm (YAGNI) | authorization-matrix.md, "Settled model" |
| AUTHZ-17 | Go↔DB được CI kiểm (#510) | `api/tests/unit/permission_catalog_sync_test.go`; hằng TS phía web vẫn chỉ nhờ review |

Lưu ý: `AdminAuthMiddleware` (§1) nay dùng phiên console, không còn API key
quản trị (RFC-022).
