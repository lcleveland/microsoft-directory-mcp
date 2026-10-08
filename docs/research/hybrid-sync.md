# Hybrid sync scenarios and source of authority

Research for #6 (part of map #1). Planning only. All facts are from Microsoft Learn / Microsoft first-party pages as read on 2026-10-08; each claim links its source. Placeholders only, nothing about any real directory.

## Answer in brief

- **Link key.** A synced object is joined to its AD object by the *sourceAnchor*, exposed in Graph as `onPremisesImmutableId` (Base64 of `objectGUID`, or of `mS-DS-ConsistencyGuid`, which Connect Sync seeds from `objectGUID`). `onPremisesSecurityIdentifier` (the AD SID) and `onPremisesDistinguishedName` / `onPremisesSamAccountName` / `onPremisesUserPrincipalName` / `onPremisesDomainName` give the server cheap cross-side lookups without decoding anything.
- **Who owns an object** is a per-object question, not a per-tenant one: `onPremisesSyncEnabled == true` means the forest is the source of authority. `null` means cloud-owned (cloud-native, or SOA-converted, where `onPremisesSyncBehavior.isCloudManaged == true`). `false` means it was synced and no longer is.
- **Writes to a synced object** fail in Graph with `400 Request_BadRequest`, "Unable to update the specified properties for on-premises mastered Directory Sync objects…". They are rejected, not silently overwritten. The server should route such writes to the AD side, not attempt them in Entra.
- **Exceptions that do work in Entra on a synced user**: licences, roles and group memberships of cloud groups; password reset via `authenticationMethod: resetPassword` (written back to AD when password writeback is on); SOA conversion itself.
- **Latency**: Connect Sync runs every 30 min by default. Cloud Sync (AD to Entra) runs every 2 min, and Cloud Sync group provisioning (Entra to AD) every 20 min. Password writeback is synchronous.
- **Triggering/observing**: Connect Sync has **no Graph trigger** (`Start-ADSyncSyncCycle` is local PowerShell on the sync server). Only `organization.onPremisesLastSyncDateTime` and per-object timestamps are visible. Cloud Sync is a Graph `synchronizationJob`: it can be read, started, restarted, and `provisionOnDemand` can push a single object.

## 1. Sync modes

| | Connect Sync | Cloud Sync | Cloud-only | AD-only |
|---|---|---|---|---|
| Engine | On-prem sync server, local config | Light agents; config and scheduling in Entra | — | — |
| AD → Entra interval | 30 min default, configurable ([scheduler](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-feature-scheduler)) | every 2 min ([what is cloud sync](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/what-is-cloud-sync)) | n/a | n/a |
| Graph control surface | Tenant feature flags only | `servicePrincipals/{id}/synchronization/jobs` | n/a | n/a |
| Password writeback | yes | yes | n/a | n/a |
| Entra → AD group provisioning | **no** (Group Writeback v2 preview deprecated) | yes (security groups) | n/a | n/a |
| Entra → AD user provisioning | no | **preview** | n/a | n/a |
| On-demand provisioning | no | yes | n/a | n/a |
| Scale ceiling | unlimited; 250K-member groups | 150K objects/domain; 50K-member groups | | |

Sources: [Cloud Sync decision guide comparison table](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/connect-to-cloud-sync-decision-guide#comparison-between-microsoft-entra-connect-and-cloud-sync); [Entra to AD provisioning setup](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/how-to-configure-entra-to-active-directory) (deployment options: groups-only GA, users/users+groups Preview).

Both clients can coexist on different domains. If both target the same domain, the Cloud Sync agent handles password writeback ([SSPR writeback](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-writeback)).

### Detecting the sync mode from Graph

- `GET /organization` returns `onPremisesSyncEnabled` (tenant-level: `true` synced / `false` was synced / `null` never) and `onPremisesLastSyncDateTime` ([organization](https://learn.microsoft.com/en-us/graph/api/resources/organization?view=graph-rest-1.0)).
- Cloud Sync presence: a service principal instantiated from application template `1a4721b3-e57f-4451-ae87-ef078703ec94` with jobs whose `templateId` is `AD2AADProvisioning` / `AD2AADPasswordHash` (and Entra-to-AD jobs) ([configure cloud sync via Graph](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/how-to-inbound-synch-ms-graph)).
- Connect Sync presence: inferred. The tenant is synced, but no Cloud Sync job covers the domain. There is no first-party Graph resource that names the Connect Sync server. (Inference, not a documented API.)
- AD-only side: the AD side alone cannot see Entra. `mS-DS-ConsistencyGuid` being populated is a hint that Connect Sync has touched the user (it writes `objectGUID` back there when it uses ConsistencyGuid as anchor) ([design concepts](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/plan-connect-design-concepts#using-ms-ds-consistencyguid-as-sourceanchor)). For a cloud-provisioned AD object, Cloud Sync stamps `msDS-ExternalDirectoryObjectId` (and `msDS-ObjectSoa = Cloud` on users) ([Entra to AD setup, mappings](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/how-to-configure-entra-to-active-directory#configure-attribute-mapping)).

## 2. How an Entra object is linked to its AD object

- **sourceAnchor = immutableId.** It is "an attribute immutable during the lifetime of an object" that "uniquely identifies an object as being the same object on-premises and in Microsoft Entra ID". Non-string source values are Base64-encoded. The default for a single forest is `objectGUID`. Since Connect Sync 1.1.524 the anchor can be `mS-DS-ConsistencyGuid`: if it is empty, Connect writes the `objectGUID` value into it and then exports. It can't be changed after export; changing it in AD produces a sync error until reverted ([design concepts](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/plan-connect-design-concepts)).
  - So for the common case `onPremisesImmutableId == base64(objectGUID bytes)`. The server can map an AD user to Entra with `$filter=onPremisesImmutableId eq '<b64>'` (filterable, requires `$select`) ([user resource](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0)). It must not assume this if a custom anchor (e.g. employeeID) was chosen at install time.
- **onPremisesSecurityIdentifier**: the AD SID, read-only, filterable `eq` ([user resource](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0)). This is a robust, anchor-independent join key for users and groups.
- **onPremisesObjectIdentifier**: carries AD `objectGUID`. It is required for Cloud Sync group provisioning to resolve members, and is populated by Connect Sync ≥ 2.2.8.0 or Cloud Sync ([group writeback with cloud sync](https://learn.microsoft.com/en-us/entra/identity/hybrid/group-writeback-cloud-sync)). Hard match is blocked if it differs from the incoming value ([sync service features](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-syncservice-features#allow-onpremisesobjectidentifier-updates-during-hard-match-enforcement)).
- **Matching** existing cloud objects on first sync: *hard match* on sourceAnchor, *soft match* on primary SMTP and optionally UPN (`SoftMatchOnUpnEnabled`). Tenant flags `BlockSoftMatchEnabled` and `BlockCloudObjectTakeoverThroughHardMatchEnabled` gate these ([sync service features](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-syncservice-features)).
- Other read-only per-object mirrors: `onPremisesDistinguishedName`, `onPremisesSamAccountName`, `onPremisesUserPrincipalName`, `onPremisesDomainName`. Their docs say these are "only populated for customers who are synchronizing … via Microsoft Entra Connect" ([user resource](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0)). Cloud Sync's Entra-to-AD docs, however, read and write `onPremisesDistinguishedName` ([Entra to AD setup](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/how-to-configure-entra-to-active-directory#move-a-provisioned-user-to-a-different-organizational-unit)). Whether Cloud Sync AD→Entra populates them is unconfirmed (see open questions).

## 3. How Graph exposes sync status and errors

| Where | What |
|---|---|
| `organization.onPremisesSyncEnabled`, `.onPremisesLastSyncDateTime` | Tenant is synced; time of last sync ([organization](https://learn.microsoft.com/en-us/graph/api/resources/organization?view=graph-rest-1.0)) |
| `user/group/orgContact.onPremisesSyncEnabled` | Per-object source of authority: `true` = forest owns it ([user](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0)) |
| `…onPremisesLastSyncDateTime` | Last time this object was synced, filterable |
| `…onPremisesProvisioningErrors` | Only `category = PropertyConflict`, `propertyCausingError` ∈ {`UserPrincipalName`, `ProxyAddress`}, plus value and time ([onPremisesProvisioningError](https://learn.microsoft.com/en-us/graph/api/resources/onpremisesprovisioningerror?view=graph-rest-1.0)). This is the duplicate-attribute-resiliency quarantine, not a general error log. |
| `user.serviceProvisioningErrors` | Errors published by federated services (e.g. Exchange), not by sync ([user](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0)) |
| `…/onPremisesSyncBehavior.isCloudManaged` | Whether SOA was converted to cloud ([onPremisesSyncBehavior](https://learn.microsoft.com/en-us/graph/api/resources/onpremisessyncbehavior?view=graph-rest-beta)) |
| `GET /directory/onPremisesSynchronization` | Tenant `features` flags: `passwordSyncEnabled`, `groupWriteBackEnabled`, `unifiedGroupWritebackEnabled`, `blockSoftMatchEnabled`, `blockCloudObjectTakeoverThroughHardMatchEnabled`, `softMatchOnUpnEnabled`, `synchronizeUpnForManagedUsersEnabled`, …; permission `OnPremDirectorySynchronization.Read.All` ([resource](https://learn.microsoft.com/en-us/graph/api/resources/onpremisesdirectorysynchronization?view=graph-rest-1.0), [features](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-syncservice-features)). Note: the `PasswordWriteback` flag here is "no longer in use", so it is not a reliable indicator. |
| Cloud Sync job `status` | `code`, `lastExecution`, `lastSuccessfulExecution`, `quarantine`, `countSuccessiveCompleteFailures`, `steadyStateLastAchievedTime`, `synchronizedEntryCountByType` ([configure via Graph](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/how-to-inbound-synch-ms-graph#review-status)) |

Connect Sync's per-object run errors (export errors, sourceAnchor change errors, the SOA-skip event 6956) live in the Synchronization Service Manager and the Windows event log on the sync server ([group SOA how-to](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-group-source-of-authority-configure#connect-sync-client)). None of that is in Graph beyond the PropertyConflict errors above.

## 4. Entra writes against a synced object

- **Rejected, not overwritten.** Graph returns `400 Bad Request`, code `Request_BadRequest`, message *"Unable to update the specified properties for on-premises mastered Directory Sync objects or objects currently undergoing migration."* ([Microsoft 365 Dev blog, 2020 breaking change](https://devblogs.microsoft.com/microsoft365dev/breaking-change-to-microsoft-graph-users-api-updates-to-on-premises-sync-enabled-user-contact-numbers-are-no-longer-allowed/)). The SOA how-tos confirm: "Because the user is managed on-premises, any write attempts to the user in the cloud fail. The error message differs for mail-enabled users, but updates still aren't allowed." The same holds for groups ([user SOA how-to](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure), [group SOA how-to](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-group-source-of-authority-configure)).
- Per-property docs mark synced-user fields read-only, e.g. `businessPhones`, `mobilePhone`, `onPremisesExtensionAttributes` ("source of authority … is the on-premises and is read-only") ([user resource](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0), [update user](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0)).
- Mail-enabled groups and DLs can't be managed via Graph at all, even when cloud-owned; that work goes to Exchange Online ([group SOA overview](https://learn.microsoft.com/en-us/entra/identity/hybrid/concept-source-of-authority-overview)).
- **Overwrite does happen in the other direction.** With Cloud Sync Entra→AD provisioning there is no reconciliation: local AD edits to a provisioned group are "overwritten when group provisioning to AD DS runs". A provisioned user moved by hand in AD is moved back on the next cycle ([group SOA limitations](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-group-source-of-authority-configure#limitations), [Entra to AD setup](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/how-to-configure-entra-to-active-directory#move-a-provisioned-user-to-a-different-organizational-unit)). So an AD-side write to a cloud-authoritative object is the one that silently loses.
- After SOA conversion, AD-side edits to that object are skipped by sync (Cloud Sync logs "Skipped"; Connect Sync logs event 6956) ([Entra to AD setup](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/how-to-configure-entra-to-active-directory#cloud-skips-changes-made-in-ad-after-soa-conversion)).

**Implication for the server:** decide routing up front from `onPremisesSyncEnabled` / `isCloudManaged` (Entra) and `msDS-ObjectSoa` / `msDS-ExternalDirectoryObjectId` (AD), rather than trying a write and interpreting the 400. Still map the 400 to a clear "this object is owned by the forest" error.

### Source of authority can now move per object

`PATCH /users|groups|contacts/{id}/onPremisesSyncBehavior {"isCloudManaged": true}` converts a synced object to cloud-owned. Afterwards `onPremisesSyncEnabled` becomes `null` and the sync client stops flowing AD changes. Requirements: Hybrid Administrator; scopes `User-` / `Group-` / `Contacts-OnPremisesSyncBehavior.ReadWrite.All`; Connect Sync ≥ 2.5.76.0 or Cloud Sync agent ≥ 1.1.1370.0. Rolling back (`false`) completes only after the next sync cycle. For users it also needs `blockCloudObjectTakeoverThroughHardMatchEnabled` temporarily turned off. User SOA prerequisites exclude on-prem Exchange, AD FS federation and password-based on-prem apps ([group SOA how-to](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-group-source-of-authority-configure), [user SOA how-to](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure), [user SOA overview](https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-overview)). The how-tos call v1.0 endpoints, while the resource reference page is listed under beta, so v1.0 availability should be verified live.

## 5. Password writeback and SSPR

- Supported by both Connect Sync and Cloud Sync. It is **synchronous**, so the caller gets immediate success or failure, and on-prem AD policy (history, complexity, filters) is enforced ([SSPR writeback](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-writeback)).
- Written back: user SSPR and change, admin reset from the Entra admin center, and **admin reset via Graph `authenticationMethod: resetPassword`**. *Not* written back: a user resetting their own password via Graph, PowerShell v1/v2, or the M365 admin center ([same](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-writeback#supported-writeback-operations)).
- `resetPassword`: `POST /users/{id}/authentication/methods/28c10230-6103-485e-b985-444c60001490/resetPassword`. It is **delegated only** (`UserAuthenticationMethod.ReadWrite.All`; no application permission). It returns `202` with a `Location` long-running-operation URL to poll. `newPassword` is required for hybrid password scenarios ([resetPassword](https://learn.microsoft.com/en-us/graph/api/authenticationmethod-resetpassword?view=graph-rest-1.0)).
- Writeback can't reset passwords of AD protected-group members (AdminSDHolder) ([SSPR writeback](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-writeback)).
- **Implication:** for a synced user the server has two password paths: (a) set it directly in AD, which reaches Entra via PHS on its own schedule, or (b) Entra `resetPassword` with writeback. Path (b) needs a delegated token and writeback enabled, and the `features.passwordWritebackEnabled` flag can't be used to detect that.

## 6. Group writeback and Cloud-to-AD group provisioning

- Connect Sync **Group Writeback v2 (preview) is deprecated and unsupported**. v1 (M365 groups to AD) remains ([group writeback with cloud sync](https://learn.microsoft.com/en-us/entra/identity/hybrid/group-writeback-cloud-sync)).
- Cloud Sync "Group Provision to AD": cloud **security** groups only (default scope clause `securityEnabled IS TRUE AND dirSyncEnabled IS FALSE AND mailEnabled IS FALSE`). They are created as **Universal** groups in `CN=Users` by default. `sAMAccountName` is random unless mapped. The job runs **every 20 min**. Groups are capped at 50K members. Only members with an AD account are written; synced members need `onPremisesObjectIdentifier`. Requires agent ≥ 1.1.2334.0, P1 licence, and Hybrid Identity Administrator ([group writeback with cloud sync](https://learn.microsoft.com/en-us/entra/identity/hybrid/group-writeback-cloud-sync), [Entra to AD setup](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/how-to-configure-entra-to-active-directory)).
- Nested groups: only the nested group is written, not its members, unless they are also in scope. There is no dual write: AD edits to the provisioned group are overwritten.

## 7. Latency, triggering and observing a cycle

| | Interval | Trigger via API? | Observe via API? |
|---|---|---|---|
| Connect Sync | 30 min default; must run at least every 7 days ([scheduler](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-feature-scheduler)) | **No.** `Start-ADSyncSyncCycle -PolicyType Delta` runs only on the sync server (local PowerShell/WinRM). | Only `organization.onPremisesLastSyncDateTime` and per-object `onPremisesLastSyncDateTime` |
| Cloud Sync AD→Entra | 2 min | `POST …/synchronization/jobs/{id}/start` and `/restart`; `provisionOnDemand` for single objects (rate limit 5 req / 10 s; `Synchronization.ReadWrite.All`, or app `Application.ReadWrite.OwnedBy`) ([configure via Graph](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/how-to-inbound-synch-ms-graph), [provisionOnDemand](https://learn.microsoft.com/en-us/graph/api/synchronization-synchronizationjob-provisionondemand?view=graph-rest-1.0)) | Job `status`; provisioning logs |
| Cloud Sync Entra→AD groups | 20 min | Same job API; on-demand | Same |
| Password writeback | Synchronous | n/a | `resetPassword` LRO `Location` |

**Implication:** after an AD-side write on a Connect Sync tenant, the server can only tell the client "visible in Entra after the next cycle (≤ ~30 min by default)". It cannot force or confirm the cycle except by polling the object's `onPremisesLastSyncDateTime` / attribute values. On Cloud Sync it could offer `provisionOnDemand`, behind a capability.

## Open questions surfaced

- Does Cloud Sync AD→Entra populate `onPremisesDistinguishedName` / `onPremisesSamAccountName` / `onPremisesDomainName`, which the Graph docs say are "Entra Connect only"?
- Is `onPremisesSyncBehavior` on Graph v1.0 or still beta? The how-tos use v1.0; the reference page is beta-only.
- Should the server expose a Connect Sync trigger by remoting `Start-ADSyncSyncCycle` to the sync server (a third connection target), or accept "wait for the cycle"?
- How should the server detect whether password writeback is actually enabled, given that the tenant feature flag is documented as unused?
- Should SOA conversion (`isCloudManaged`) be a capability the server offers? It moves an object's source of authority and so changes which side owns writes.
