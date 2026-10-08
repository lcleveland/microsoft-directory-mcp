# Microsoft Graph facts for the Entra side

Research for [#4](https://github.com/lcleveland/microsoft-directory-mcp/issues/4). This is input to the Entra client and auth decisions, not the decisions themselves. Sources were read on 2026-10-08. Every claim links to the Microsoft Learn page or source file it came from. Tenant values are placeholders (`{tenant}`, `{client-id}`).

## Summary

- **Auth:** app-only client credentials, `POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` with `scope=https://graph.microsoft.com/.default`. A client secret works. A certificate assertion is a PS256-signed JWT that can be built with the stdlib. Tokens last 60-90 minutes, there is no refresh token, and you simply fetch again.
- **Sovereign clouds:** two host strings change (login host and Graph host). There are four fixed pairs, so a `cloud` enum is enough.
- **v1.0 covers every v1 job.** The only beta-only thing found is **non-interactive, service-principal and managed-identity sign-ins** (the `signInEventTypes` filter). Interactive sign-ins are on v1.0.
- **Paging:** follow `@odata.nextLink` verbatim. Re-send `ConsistencyLevel` on every page. Never use a token from a retried request.
- **Advanced queries** (`ne`, `not`, `endsWith`, `$search`, `$count`, `$filter`+`$orderby`) only work on directory objects, and need `ConsistencyLevel: eventual` plus `$count=true` (`$search` needs only the header). They don't support `$expand`.
- **Throttling:** 429 + `Retry-After` in seconds. The limits that will actually bite are **Identity Protection / Conditional Access at 1 req/s per tenant** and **audit/sign-in logs at 5 req/10 s per app per tenant**.
- **$batch:** 20 requests per batch. Each item is throttled on its own and must be retried on its own.
- **msgraph-sdk-go v1.104.0 vs hand-rolled (measured):** 27.0 MB vs 6.1 MB stripped binary, 39 s vs 4 s Nix compile, a 226 MB vendor FOD vs none, 48 modules vs 1. Its retry handler also **replays POST/PATCH/PUT** on 429/503/504, which is the same write-replay problem that sank gofalcon in [falcon-mcp ADR 0001](https://github.com/lcleveland/falcon-mcp/blob/main/docs/adr/0001-hand-rolled-client-not-gofalcon.md). **Recommendation: hand-roll**, on the falcon/ninjaone client shape.

## 1. App-only auth

Source: [OAuth 2.0 client credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow), [certificate credentials](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials).

Token request (`application/x-www-form-urlencoded`):

| Field | Secret | Certificate |
|---|---|---|
| `client_id` | `{client-id}` | `{client-id}` |
| `scope` | `https://graph.microsoft.com/.default` | same |
| `grant_type` | `client_credentials` | `client_credentials` |
| credential | `client_secret=…` (HTTP Basic also accepted) | `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion=<JWT>` |

- `/.default` asks for every application permission an admin has granted for that resource. All scopes must belong to one resource.
- App-only means **application permissions only**. Delegated permissions are unavailable "because there is no user". Admin consent is a one-time step done outside the server.
- The response is `{"token_type":"Bearer","expires_in":3599,"access_token":…}`. **No refresh token is issued** in this flow. "When the token expires, repeat the request to the `/token` endpoint". Errors come back as 400 JSON with `error`, `error_description` and `error_codes` (AADSTS numbers).
- Microsoft says not to parse Graph access tokens ("Don't attempt to validate or read tokens for any API you don't own"). Cache by `expires_in` and don't read `exp` out of the token.

**Certificate assertion JWT.** Microsoft calls this the "higher level of assurance" option:

- Header: `alg` **PS256** (RSA-PSS), `typ` JWT, and `x5t#S256`, which is the base64url SHA-256 of the certificate's DER.
- Claims: `aud` = `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`, `iss` = `sub` = `{client-id}`, a random `jti` (GUID), `nbf` and `iat` set to now, and `exp` set to "5-10 minutes after `nbf` at most".
- Go needs only `crypto/rsa.SignPSS`, `crypto/sha256`, `crypto/x509` and `encoding/pem`/`base64`. That is about 50 lines with no JWT library, as long as the key is supplied as PEM. A PFX would need `x/crypto/pkcs12`, so require PEM.
- Workload identity federation uses the same `client_assertion` fields, but with a JWT issued by an external IdP. It isn't relevant to a loopback NixOS host and is noted only for completeness.

**Token lifetime** ([configurable token lifetimes](https://learn.microsoft.com/en-us/entra/identity-platform/configurable-token-lifetimes)): access tokens get a random 60-90 minutes (75 on average). A token lifetime policy can set 10 minutes to 1 day. CAE-capable clients can receive 24-28 hours, which doesn't matter for a hand-rolled client that doesn't advertise CAE. Implication: cache the token, refresh it about 5 minutes before `expires_in` runs out, and force one re-fetch on a 401. This is the ninjaone `bearer()` pattern again.

## 2. Sovereign clouds

Source: [national cloud deployments](https://learn.microsoft.com/en-us/graph/deployments).

| Cloud | Token host | Graph host |
|---|---|---|
| Global (including M365 **GCC**) | `https://login.microsoftonline.com` | `https://graph.microsoft.com` |
| US Gov L4 (**GCC High**) | `https://login.microsoftonline.us` | `https://graph.microsoft.us` |
| US Gov L5 (**DoD**) | `https://login.microsoftonline.us` | `https://dod-graph.microsoft.us` |
| China (21Vianet) | `https://login.chinacloudapi.cn` | `https://microsoftgraph.chinacloudapi.cn` |

- The `scope` follows the Graph host, for example `https://graph.microsoft.us/.default`. The assertion `aud` follows the token host.
- "Access tokens acquired for a national cloud deployment are not interchangeable" with other clouds.
- API availability differs per cloud, and each API page has a per-cloud table. For example, `riskyUsers` is **not** available in 21Vianet ([riskyUser list](https://learn.microsoft.com/en-us/graph/api/riskyuser-list?view=graph-rest-1.0)).
- Config shape: a `cloud` enum (`global|usgov|usgovdod|china`) mapped to a fixed host pair. A free-form base URL is only needed for the VM-test stub. The SDK has no cloud enum either, only `NewGraphServiceClientWithCredentialsAndHosts` plus a manual base URL ([graph_service_client.go](https://github.com/microsoftgraph/msgraph-sdk-go/blob/main/graph_service_client.go), [issue #235](https://github.com/microsoftgraph/msgraph-sdk-go/issues/235), still open).

## 3. v1.0 vs beta per resource

Every resource below is on **v1.0**. Licence and least-privilege application permission come from each API page.

| Area | Endpoint(s) (v1.0) | Least-privilege app permission (read / write) | Licence | Notes |
|---|---|---|---|---|
| Users | `/users`, `/users/{id}` | `User.Read.All` / `User.ReadUpdate.All` (narrower: `User-PasswordProfile.ReadWrite.All`, `User.EnableDisableAccount.All`+`User.Read.All`, `User-Phone…`, `User-Mail…`) | Free | [user-update](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0). Password reset by `passwordProfile` "can't be used for federated users". |
| Last sign-in | `/users?$select=signInActivity` | `AuditLog.Read.All` | **P1** (per Microsoft Q&A, not stated on the resource page) | [signInActivity](https://learn.microsoft.com/en-us/graph/api/resources/signinactivity?view=graph-rest-1.0). `lastSuccessfulSignInDateTime` exists since 2023-12 and isn't backfilled. Throttled at 10 req/min. |
| Groups | `/groups`, `/members`, `/transitiveMembers` | `GroupMember.Read.All` or `Group.Read.All` | Free | `transitiveMembers` costs 5 RU. |
| Devices (Entra) | `/devices` | `Device.Read.All` | Free | |
| Sign-ins | `/auditLogs/signIns` | `AuditLog.Read.All` (plus `Policy.Read.All` to see `appliedConditionalAccessPolicies`) | Retention is 7 d Free and 30 d P1/P2. The API page states no licence, but Microsoft Q&A answers say API access needs **P1**. Verify on a live tenant. | [signin-list](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0). **Interactive only on v1.0.** Non-interactive, service-principal and managed-identity sign-ins need **beta** `signInEventTypes/any(...)` ([beta page](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-beta)). Page size defaults to and maxes at 1,000. Always filter on `createdDateTime` to avoid timeouts. |
| Directory audits | `/auditLogs/directoryAudits` | `AuditLog.Read.All` | Free (7 d) / P1 (30 d) | [retention](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention) |
| Risky users | `/identityProtection/riskyUsers` (+ `confirmCompromised`, `dismiss`) | `IdentityRiskyUser.Read.All` / `.ReadWrite.All` | **P2** ("Microsoft Graph: All risk reports" is P2 only) | [riskyuser-list](https://learn.microsoft.com/en-us/graph/api/riskyuser-list?view=graph-rest-1.0), [ID Protection licensing](https://learn.microsoft.com/en-us/entra/id-protection/overview-identity-protection#license-requirements). `$top` max is 500. Not available in 21Vianet. |
| Conditional Access | `/identity/conditionalAccess/policies` | `Policy.Read.All` / `Policy.ReadWrite.ConditionalAccess` (+`Policy.Read.All`) | P1 | [list policies](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0). Supports `$skip/$top/$count/$filter/$orderby/$select`. |
| Directory roles | `/roleManagement/directory/roleDefinitions`, `/roleAssignments`; legacy `/directoryRoles` | `RoleManagement.Read.Directory` | Free | `directoryRoles` **doesn't page** ([paging](https://learn.microsoft.com/en-us/graph/paging)) |
| PIM | `/roleManagement/directory/roleEligibilitySchedules`, `roleAssignmentSchedules`, `…ScheduleRequests`, `…Instances` | `RoleEligibilitySchedule.Read.Directory` etc. | P2 / ID Governance ([PIM licensing](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure#license-requirements)) | [list eligibility schedules](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleeligibilityschedules?view=graph-rest-1.0) |
| App registrations / SPs | `/applications`, `/servicePrincipals` | `Application.Read.All` | Free | `GET applications` costs 2 RU |
| Licences | `/subscribedSkus`, `/users/{id}/licenseDetails`, `POST /users/{id}/assignLicense` | `LicenseAssignment.Read.All` / `LicenseAssignment.ReadWrite.All` | Free | Not re-verified page by page. Confirm in #11/#14. |
| Intune managed devices | `/deviceManagement/managedDevices` + actions `retire`, `wipe`, `syncDevice`, `rebootNow`, `shutDown`, `remoteLock`, `resetPasscode`, `locateDevice`, `windowsDefenderScan`, `cleanWindowsDevice`, … | `DeviceManagementManagedDevices.Read.All` / `.PrivilegedOperations.All` for actions | **Active Intune licence** for the tenant | [managedDevice v1.0](https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-manageddevice?view=graph-rest-1.0). Actions return no body, and their outcome shows later in `deviceActionResults`. |

Takeaway: a client pinned to `v1.0` covers the v1 jobs. Beta is needed only if "all sign-in types" is in scope, which is a product question (see the end). Beta APIs are "not supported" for production use and "subject to change" (banner on every beta page).

## 4. Paging

Source: [paging](https://learn.microsoft.com/en-us/graph/paging).

- Follow `@odata.nextLink` **verbatim** until it is absent. It carries `$skiptoken` or `$skip` and the original query: "Don't try to extract the `$skiptoken` … and use it in a different request."
- A page may hold zero items. Default and maximum `$top` differ per API (`/users` defaults to 100, sign-ins default to and max at 1,000, `riskyUsers` maxes at 500). An over-large `$top` may be ignored, clamped, or rejected.
- On directory resources, custom headers such as **`ConsistencyLevel` are not carried to later pages**, so set them again on every page. `@odata.count` comes back on the **first page only**.
- `DirectoryPageTokenNotFoundException`: if a page request is retried, continue from the token of the last *successful non-retry* response, never from the token the retry returned.
- `directoryRole` and its members don't page.

Fit with the sibling paging contract: the opaque cursor **is** the nextLink. It should be wrapped (for example base64 of the URL plus a host check), so a caller can't point the client at an arbitrary host. Re-check on decode that the host equals the configured Graph host.

## 5. $filter, $search and advanced queries

Source: [advanced queries](https://learn.microsoft.com/en-us/graph/aad-advanced-queries), [$search](https://learn.microsoft.com/en-us/graph/search-query-parameter).

- **Scope:** directory objects and their relationships only. That means users, groups, devices, applications, servicePrincipals, orgContacts, administrativeUnits, appRoleAssignments and oAuth2PermissionGrants. It does **not** cover audit logs, Intune or CA, which have their own per-API `$filter` support.
- **Needs advanced query parameters** (`ConsistencyLevel: eventual` **and** `$count=true`):
  - `ne` and `not`
  - `endsWith`, only on `mail`, `otherMails`, `userPrincipalName` and `proxyAddresses`
  - `/$count eq 0` style collection counts
  - `$filter` together with `$orderby`
  - `$count`, both as a segment and as a parameter. Without the header the segment errors and `?$count=true` is **silently ignored**.
  - `$filter` on relationships, OData casts such as `transitiveMemberOf/microsoft.graph.group`
  - `$search`, which needs the header only
- **Not supported with advanced queries:** `$expand`. Azure AD B2C tenants support none of this.
- **`$search` syntax:** `$search="displayName:foo" OR "mail:bar"`. Every clause is quoted `"property:text"`, the operators are uppercase `AND`/`OR`, and parentheses are allowed. Real tokenized search applies only to `displayName` and `description`. Other properties fall back to `startsWith`. There is no "contains". There is a known issue with `&` in values.
- **`eventual` means the index can lag writes.** A just-created object may not show up in advanced queries yet, so read back by id after a write.
- In `$batch`, put `ConsistencyLevel` in each item's `headers`.

Design implication: the client should add `ConsistencyLevel: eventual` + `$count=true` whenever the tool passes `$search` or any advanced operator. The simplest version: always send them on directory-object list calls that have a filter or search. Cost: no `$expand` on those calls.

## 6. Throttling

Sources: [throttling guidance](https://learn.microsoft.com/en-us/graph/throttling), [service limits](https://learn.microsoft.com/en-us/graph/throttling-limits).

- A throttled call gets **429 Too Many Requests** with a **`Retry-After` header in seconds** (for example `Retry-After: 10`). Wait that long and retry. If the header is missing, use exponential backoff. Usage keeps counting during the throttle, so immediate retries make things worse.
- Global: 130,000 requests per 10 s per app across all tenants, which is irrelevant at our scale.
- **Identity and access (directory)**, measured in resource units (RU) per app+tenant per 10 s:
  - S (<50 users): 3,500. M (50-500 users): 5,000. L (>500 users): 8,000.
  - Most requests cost 1 RU. `GET applications` costs 2, `transitiveMembers` 5, `getByIds` 5, `isMemberOf` 4. `$select` costs 1 less, `$expand` 1 more, and `$top` under 20 costs 1 less.
  - Writes: 3,000 per 150 s per app+tenant.
  - Response headers: `x-ms-resource-unit` and `x-ms-throttle-limit-percentage`, which runs from 0.8 to 1.8 and is a useful early-slowdown signal, like Falcon's `X-Ratelimit-Remaining`.
- **Identity Protection + Conditional Access: 1 request per second per tenant, shared by all apps.** This is the tightest limit.
- **Audit logs / sign-ins:** 5 requests per 10 s per app per tenant. `signInActivity`: 10 requests per minute.
- **Intune:** 1,000 requests per 20 s per app per tenant (devices service 2,000). Writes and actions are limited to 100 per 20 s (devices service 200).
- Writes and reads are throttled separately ("writes are throttled but reads are still permitted").

Client implication: retry **reads only** on 429/503/504, honour `Retry-After` up to a cap (about 60 s, within the context deadline), and never auto-retry writes (house rule). Paging loops over sign-ins must expect the 5-per-10-s limit. The 200-item / 60 KiB caps already keep requests per tool call low.

## 7. $batch

Source: [JSON batching](https://learn.microsoft.com/en-us/graph/json-batching), [throttling and batching](https://learn.microsoft.com/en-us/graph/throttling#throttling-and-batching).

- Send `POST /v1.0/$batch` with `{"requests":[{id, method, url (relative, e.g. "/users"), headers?, body?}]}`. A `body` requires `headers.Content-Type`. The limit is **20** requests per batch.
- Responses come back in **any order**, matched by `id`. The batch itself returns 200 even when items fail, because each item has its own `status`. Order is only guaranteed with `dependsOn`, and a failed dependency gives the dependent item 424. A batch should be "fully sequential or fully parallel".
- Every item is throttled **individually**, so an item can come back 429 with its own `Retry-After` inside a 200 batch. SDKs don't auto-retry batched items.
- Uses: fanning out per-object lookups (for example `licenseDetails` for N users), and getting around URL length limits for long filters.
- Verdict: optional for v1. A hand-rolled `Batch` is about 40 lines. Leave it out until a tool actually needs fan-out.

## 8. msgraph-sdk-go vs hand-rolled

### Measured (same method as [gofalcon-vs-hand-rolled](https://github.com/lcleveland/falcon-mcp/blob/main/docs/research/gofalcon-vs-hand-rolled.md))

Two throwaway programs were built with nixpkgs `go1.26.8` through `buildGoModule`, using `CGO_ENABLED=0` and `-ldflags "-s -w"`, on 32 cores, in a scratch directory outside the repo. Both call the same 12 list endpoints: users, groups, devices, signIns, directoryAudits, riskyUsers, CA policies, roleAssignments, applications, servicePrincipals, subscribedSkus and managedDevices.

- **SDK:** `msgraph-sdk-go v1.104.0` + `azidentity v1.14.1` (client secret credential).
- **Hand-rolled:** stdlib `net/http` + `encoding/json` with a form-POST token request.

| | msgraph-sdk-go v1.104.0 | Hand-rolled (stdlib) |
|---|---|---|
| Stripped static binary | **27.0 MB** | **6.1 MB** |
| `buildGoModule` compile (vendor already fetched) | **39 s** | **4 s** |
| Vendor FOD (`vendorHash`) | **226 MB** (217 MB of it msgraph-sdk-go) | none |
| `go mod download` module cache during `go mod tidy` | 968 MB (541 MB of it Azure SDK modules pulled during resolution) | 0 |
| Modules in build list (`go list -m all`) | 48 | 1 |

The SDK pulls in seven `kiota-*` modules, `azcore`/`azidentity`/MSAL, `golang-jwt`, `opentelemetry` (otel, metric, trace, auto/sdk), `std-uritemplate`, `x/crypto`, `x/net`, `x/sys` and `x/text`.

### Maturity and behaviour

- **Release cadence:** v1.x, regenerated and released about every 2-4 weeks. There were 30 releases from v1.75.0 (2025-06) to v1.104.0 (2026-10-06). Each bump changes `vendorHash` on a 200+ MB FOD. The repo has MIT licence, 332 stars and 47 open issues ([GitHub](https://github.com/microsoftgraph/msgraph-sdk-go/releases)).
- **Beta is a separate module,** `msgraph-beta-sdk-go`, still v0.x (v0.166.0, 2026-09-02). It is a second huge generated tree with its own types. Supporting the one beta sign-in filter through the SDK would mean pulling in both.
- **Build cost is a known issue:** [#129](https://github.com/microsoftgraph/msgraph-sdk-go/issues/129) reported `go test` going from 7 s to 8 m 50 s and lint from 36 s to 7 m 13 s after importing the `models` package. The reporter fixed it by switching to plain `net/http`. Also see [#753](https://github.com/microsoftgraph/msgraph-sdk-go/issues/753), "adds 10 seconds to build time". The `models` package is too big for pkg.go.dev to render.
- **Retries replay writes.** kiota-http-go's `RetryHandler` retries on 429/503/504, up to 3 times by default (absolute maximum 10, 180 s cumulative). Its `isRetriableRequest` returns true for every method, and for POST/PUT/PATCH whenever the body length is known ([retry_handler.go](https://github.com/microsoft/kiota-http-go/blob/main/retry_handler.go)). So a `wipe`, `assignLicense` or password reset could be sent twice. This conflicts with the house rule "writes never auto-retried", the same reason given in falcon-mcp ADR 0001.
- **Typed models,** so fields that the generated model lacks are dropped. That includes beta-only fields seen through v1.0 objects and anything Microsoft adds before the next regeneration. The MCP tool layer wants raw JSON to project and truncate. The SDK can also do raw requests through the adapter, but then most of what it provides goes unused.
- **No cloud enum** (see §2). The SDK does provide a page iterator and a batch helper in `msgraph-sdk-go-core`, but each is about 30-40 lines to write by hand.

### What a hand-rolled client must replicate

1. **Token source:** secret or PEM-cert assertion (PS256, `x5t#S256`). Cache with early refresh and force-refresh once on 401. Token and Graph hosts come from the cloud enum.
2. **`Do(method, path, query, body, headers)`** returning raw JSON. A version segment fixed at `v1.0`, with an opt-in `beta` per call if the sign-in-types question says yes.
3. **Paging:** follow `nextLink` verbatim, re-send `ConsistencyLevel` on each page, apply the host check on cursor decode, and keep the last-successful-token rule.
4. **Advanced-query helper:** add `ConsistencyLevel: eventual` + `$count=true` when using `$search` or advanced operators.
5. **Retry:** reads only, 429/503/504, honour `Retry-After` in seconds with a cap and the context deadline. Optionally slow down early when `x-ms-throttle-limit-percentage` is high.
6. **Error mapping:** Graph's `{"error":{"code","message","innerError":{"request-id","date"}}}`. Surface `code` and `request-id`. Give hints for `Authorization_RequestDenied` (missing permission) and the licence errors (P1/P2/Intune) that the startup-probe question cares about.
7. Optional `$batch` (§7).

Each item gets an httptest case, as in falcon-mcp.

## Newly surfaced questions

- Are non-interactive, service-principal and managed-identity sign-ins in v1 scope? That is the only reason found to call `beta`.
- Licence-gated features (P1 sign-ins and `signInActivity`, P2 risky users and PIM, the Intune licence for managed devices): should the startup probe detect these from `subscribedSkus` and hide actions, or only map the error at call time? This feeds the map's "Startup probe" item.
- Credential type for v1: secret only, certificate only, or both? A certificate is the stronger option and is stdlib-only if PEM is required.
- Should `cloud` be configurable in v1, or global only with the enum left for later?
- Writes to **synced** users (Connect or Cloud Sync) are refused for source-of-authority attributes. Should `entra_*` write tools detect `onPremisesSyncEnabled` and point to the `ad_*` side instead? This affects every sync mode the map requires.
