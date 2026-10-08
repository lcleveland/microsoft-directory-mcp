# Entra permissions and licensing matrix

Research for [#5](https://github.com/lcleveland/microsoft-directory-mcp/issues/5). Researched 2026-10-08.

Sources: Microsoft Learn, read as raw Markdown (`?accept=text/markdown`). Graph v1.0 per-API pages are cited by slug, so `user-update` means `https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0`. Concept pages are cited by path under `learn.microsoft.com/en-us/`.

Labels: **[src]** was read on a first-party page. **[2nd]** comes from secondary sources only. **[unverified]** needs a live tenant to confirm. **[doc-quirk]** marks a place where the Learn page looks wrong or contradicts another Learn page; the reading we chose is stated next to it.

All examples use placeholders. Nothing here describes a real tenant.

## TL;DR

1. **The app gets application permissions only.** It authenticates with client credentials. Every v1 read has an app-only permission, except four reads whose v1.0 pages say "Application: Not supported": `/users/{id}/ownedDevices`, `/users/{id}/registeredDevices`, `/users/{id}/licenseDetails` and `authenticationMethod: resetPassword`. Each has a workaround, listed below.
2. **Licences gate four areas:**
   - **Entra ID P1:** sign-in logs, `signInActivity`, `userRegistrationDetails`, and creating or editing Conditional Access.
   - **Entra ID P2:** riskyUsers, riskDetections and PIM schedules.
   - **Intune:** `/deviceManagement/managedDevices` and device actions.
   - **Workload ID Premium:** service-principal risk.
   Everything else in the v1 jobs works on Entra ID Free: users, groups, devices, directory audits (7-day retention on Free), roles, licences and policy reads.
3. **Graph permissions alone are not enough for sensitive writes on privileged targets.** The sensitive writes are password reset, enable/disable, delete/restore, changing phones/otherMails/UPN, and revoke sessions. For app-only calls, the service principal also needs an **Entra directory role**:
   - **User Administrator** covers non-admins and a few low admin roles. Password reset requires it even for ordinary users.
   - **Privileged Authentication Administrator** covers *all* admins.
   - Adding members to role-assignable groups also needs `RoleManagement.ReadWrite.Directory`.
4. **A probe can tell "no permission" from "no licence" without parsing error bodies:**
   - **Permissions:** read the `roles` claim of the app-only token. It lists the granted Graph application permissions.
   - **Licences:** read `GET /subscribedSkus`, which needs `LicenseAssignment.Read.All`. Look for service plans `AAD_PREMIUM`, `AAD_PREMIUM_P2`, `INTUNE_A` and `AAD_WRKLDID_P2`.
   - **Directory roles:** read `GET /roleManagement/directory/roleAssignments?$filter=principalId eq '{oid}'`.
   - **Fallback:** if those calls fail, use one `$top=1` read probe per group. Its 403 body code (`Authentication_RequestFromNonPremiumTenantOrB2CTenant` versus `Authorization_RequestDenied`) usually tells licence from permission. Treat it as a hint, not a contract.

## Matrix

"Least priv." is the **Application** row of each page's permissions table. "Lic." is the licence the tenant needs. Free means Entra ID Free, which every tenant has.

### Identity lifecycle (users, groups)

| Operation | Graph call | Least priv. (application) | Lic. | Directory role for app-only | Source |
|---|---|---|---|---|---|
| List / get users | `GET /users`, `/users/{id}` | `User.Read.All` | Free | none | [src] `user-list`, `user-get` |
| …with `signInActivity` | `$select=signInActivity` | `User.Read.All` + `AuditLog.Read.All` | **P1** | none | [src] `user-list` ("require a Microsoft Entra ID P1 or P2 license and the `AuditLog.Read.All` permission") |
| User's group/role memberships | `GET /users/{id}/memberOf` | `Directory.Read.All` | Free | none | [src] `user-list-memberof` |
| Create user | `POST /users` | `User.Create` | Free | none | [src] `user-post-users` |
| Update ordinary properties (title, department, …) | `PATCH /users/{id}` | `User.ReadWrite.All` | Free | none | [src] `user-update` |
| Set manager | `PUT /users/{id}/manager/$ref` | `User.ReadWrite.All` | Free | none | [src] `user-post-manager` |
| Enable / disable | `PATCH accountEnabled` | `User.EnableDisableAccount.All` + `User.Read.All` | Free | Needed when the target holds an admin role. See [sensitive actions](#directory-roles-for-sensitive-writes). | [src] `user-update` |
| Reset password | `PATCH passwordProfile` | `User-PasswordProfile.ReadWrite.All` | Free | **At least User Administrator, always.** Privileged Authentication Administrator for all admins. | [src] `user-update` ("In app-only scenarios, the calling app must be assigned a supported permission *and* at least the *User Administrator* … role") |
| Change phones / otherMails | `PATCH businessPhones, mobilePhone, otherMails` | `User-Phone.ReadWrite.All` / `User-Mail.ReadWrite.All` | Free | When the target is an admin | [src] `user-update` |
| Revoke sessions | `POST /users/{id}/revokeSignInSessions` | `User.RevokeSessions.All` | Free | When the target is an admin (`resources/users` lists "invalidate refresh tokens" beside password reset) | [src] `user-revokesigninsessions`, `resources/users` |
| Delete user | `DELETE /users/{id}` | `User.ReadWrite.All` | Free | When the target has an admin role ("isn't enough privilege to delete users with privileged administrative roles") | [src] `user-delete` |
| Restore deleted user | `POST /directory/deletedItems/{id}/restore` | `User.DeleteRestore.All` | Free | When the target has an admin role | [src] `directory-deleteditems-restore` |
| List groups | `GET /groups` | `GroupMember.Read.All` or `Group.Read.All` | Free | none | [src] `group-list` **[doc-quirk]**: the page's "least privileged" cell names `Group-NestingSupport.ReadWrite.All`, a write permission. We read it as table damage. |
| Create group | `POST /groups` | `Group.Create` | Free | none | [src] `group-post-groups` |
| Add / remove member (user or group) | `POST/DELETE /groups/{id}/members` | `GroupMember.ReadWrite.All` (add `Device.ReadWrite.All` to add a device) | Free | For **role-assignable groups**, also `RoleManagement.ReadWrite.Directory` | [src] `group-post-members`, `group-delete-members` |

### Security and audit

| Operation | Graph call | Least priv. | Lic. | Source |
|---|---|---|---|---|
| Directory audit log | `GET /auditLogs/directoryAudits` | `AuditLog.Read.All` | Free (7-day retention; 30 days on P1/P2) | [src] `directoryaudit-list`; `entra/identity/monitoring-health/reference-reports-data-retention` |
| Sign-in log | `GET /auditLogs/signIns` | `AuditLog.Read.All` (+ `Policy.Read.All` to receive `appliedConditionalAccessPolicies`, which is otherwise silently omitted) | **P1** | [src] `signin-list`; `entra/identity/monitoring-health/howto-analyze-activity-logs-with-microsoft-graph` ("Accessing sign-in reports requires a Microsoft Entra ID P1 or P2 license") |
| MFA / SSPR registration report | `GET /reports/authenticationMethods/userRegistrationDetails` | `AuditLog.Read.All` | **P1** | [src] `authenticationmethodsroot-list-userregistrationdetails`; `entra/identity/authentication/howto-authentication-methods-activity` |
| A user's auth methods | `GET /users/{id}/authentication/methods` | `UserAuthenticationMethod.Read.All` (or per-method `UserAuthMethod-Phone.Read.All` etc.) | Free | [src] `authentication-list-methods`, `authentication-list-phonemethods` |
| Delete an auth method | `DELETE …/microsoftAuthenticatorMethods/{id}` | `UserAuthenticationMethod.ReadWrite.All` | Free | [src] `microsoftauthenticatorauthenticationmethod-delete` |
| Issue a Temporary Access Pass | `POST /users/{id}/authentication/temporaryAccessPassMethods` | `UserAuthMethod-TAP.ReadWrite.All` | Free | [src] `authentication-post-temporaryaccesspassmethods` **[doc-quirk]**: the page's least-privileged cell says `UserAuthMethod-TAP.Read.All`, a read permission, for a create. |
| Risky users | `GET /identityProtection/riskyUsers` | `IdentityRiskyUser.Read.All` | **P2** | [src] `riskyuser-list`, `resources/riskyuser` |
| Confirm compromised / dismiss risk | `POST …/riskyUsers/confirmCompromised` and `/dismiss` | `IdentityRiskyUser.ReadWrite.All` | **P2** | [src] `riskyuser-confirmcompromised`, `riskyuser-dismiss` |
| Risk detections | `GET /identityProtection/riskDetections` | `IdentityRiskEvent.Read.All` | **P2** | [src] `riskdetection-list` says "P1 or P2", but `entra/id-protection/overview-identity-protection` says "Microsoft Graph: All risk reports" requires P2. **[doc-quirk]**: we assume P2. |
| Service principal risk | `GET /identityProtection/servicePrincipalRiskDetections` | `IdentityRiskEvent.Read.All` | **Workload ID Premium** | [src] `identityprotectionroot-list-serviceprincipalriskdetections` |
| Role assignments (active) | `GET /roleManagement/directory/roleAssignments` | `RoleManagement.Read.Directory` | Free | [src] `rbacapplication-list-roleassignments` |
| Role definitions / activated roles | `GET /roleManagement/directory/roleDefinitions`, `/directoryRoles` | `RoleManagement.Read.Directory` | Free | [src] `rbacapplication-list-roledefinitions`, `directoryrole-list` |
| PIM eligible assignments | `GET /roleManagement/directory/roleEligibilitySchedules` | `RoleEligibilitySchedule.Read.Directory` | **P2** (or ID Governance / Entra Suite) | [src] `rbacapplication-list-roleeligibilityschedules`; `entra/id-governance/licensing-fundamentals` |
| Assign a directory role | `POST /roleManagement/directory/roleAssignments` | `RoleManagement.ReadWrite.Directory` | Free (assigning roles *to groups* needs P1) | [src] `rbacapplication-post-roleassignments`; `entra/identity/role-based-access-control/custom-overview` |
| App registrations / enterprise apps | `GET /applications`, `/servicePrincipals` | `Application.Read.All` | Free | [src] `application-list`, `serviceprincipal-list` |

### Policy and config

| Operation | Graph call | Least priv. | Lic. | Source |
|---|---|---|---|---|
| Conditional Access policies | `GET /identity/conditionalAccess/policies` | `Policy.Read.All` | **P1** to create/edit. Reads on an unlicensed or lapsed tenant: **[unverified]**. Learn says lapsed tenants "can view and delete … but can't update". | [src] `conditionalaccessroot-list-policies`; `entra/identity/conditional-access/overview` |
| Create / update CA policy | `POST/PATCH …/policies` | `Policy.Read.All` **and** `Policy.ReadWrite.ConditionalAccess` | **P1** (risk conditions need **P2**) | [src] `conditionalaccessroot-post-policies`, `conditionalaccesspolicy-update` |
| Named locations | `GET /identity/conditionalAccess/namedLocations` | `Policy.Read.All` | P1 (CA feature) | [src] `conditionalaccessroot-list-namedlocations` |
| Authentication methods policy | `GET /policies/authenticationMethodsPolicy` | `Policy.Read.AuthenticationMethod` | Free | [src] `authenticationmethodspolicy-get` |
| Authorization policy (guest/user defaults) | `GET /policies/authorizationPolicy` | `Policy.Read.All` | Free | [src] `authorizationpolicy-get` |
| Device registration policy | `GET /policies/deviceRegistrationPolicy` | `Policy.Read.DeviceConfiguration` | Free | [src] `deviceregistrationpolicy-get` |
| Tenant / organization | `GET /organization` | `Organization.Read.All` | Free | [src] `organization-get` |

### Devices and licensing

| Operation | Graph call | Least priv. | Lic. | Source |
|---|---|---|---|---|
| Entra device objects | `GET /devices` | `Device.Read.All` | Free | [src] `device-list` |
| Enable/disable or update an Entra device | `PATCH /devices/{id}` | `Device.ReadWrite.All` | Free | [src] `device-update` |
| Delete an Entra device | `DELETE /devices/{id}` | `Device.ReadWrite.All` | Free | [src] `device-delete` |
| A user's devices | `GET /users/{id}/ownedDevices` and `/registeredDevices` | **Application: Not supported** per the v1.0 pages | Free | [src] `user-list-owneddevices`, `user-list-registereddevices`. **[unverified]** whether this is only a doc gap. Workaround: `GET /devices/{id}/registeredOwners` per device, or Intune `managedDevices?$filter=userPrincipalName eq '…'` |
| BitLocker recovery keys | `GET /informationProtection/bitlocker/recoveryKeys` | `BitlockerKey.ReadBasic.All` (metadata) / `BitlockerKey.Read.All` (key) | Free | [src] `bitlocker-list-recoverykeys`, `bitlockerrecoverykey-get` |
| Intune managed devices | `GET /deviceManagement/managedDevices` | `DeviceManagementManagedDevices.Read.All` | **Intune** | [src] `intune-devices-manageddevice-list`; `resources/intune-graph-overview` ("still requires that the Intune service is correctly licensed") |
| Intune actions: sync, reboot, retire, wipe | `POST …/managedDevices/{id}/syncDevice` (and `rebootNow`, `retire`, `wipe`) | `DeviceManagementManagedDevices.PrivilegedOperations.All` | **Intune** | [src] `intune-devices-manageddevice-syncdevice`, `-rebootnow`, `-retire`, `-wipe` |
| Tenant SKUs and seat counts | `GET /subscribedSkus` | `LicenseAssignment.Read.All` | Free | [src] `subscribedsku-list` |
| A user's licences | `GET /users/{id}?$select=assignedLicenses,licenseAssignmentStates` | `User.Read.All` | Free | [src] `user-get`. `/users/{id}/licenseDetails` is **Application: Not supported** [src] `user-list-licensedetails`, so join `assignedLicenses[].skuId` to `/subscribedSkus` instead. |
| Assign / remove a licence | `POST /users/{id}/assignLicense` | `LicenseAssignment.ReadWrite.All` | Free | [src] `user-assignlicense` |
| Reprocess group-based licensing | `POST /users/{id}/reprocessLicenseAssignment` | `User.ReadWrite.All` | Free (group-based licensing itself needs P1) | [src] `user-reprocesslicenseassignment` |

### Not possible app-only

- **`authenticationMethod: resetPassword`** (the "generate a temporary password" method) is delegated only [src] `authenticationmethod-resetpassword`. Use `PATCH passwordProfile` instead.
- `graph/resolve-auth-errors` still says "there is no application permission … that allow[s] resetting user passwords". That is **stale [doc-quirk]**: `user-update`, updated 2026-07, documents app-only `passwordProfile` updates with `User-PasswordProfile.ReadWrite.All` plus the User Administrator role.
- `passwordProfile` "can't be used for federated users" [src] `user-update`. For synced users, see the open question on sync mode.

## Directory roles for sensitive writes

`resources/users` defines the **sensitive actions**:

- `accountEnabled`
- `businessPhones`, `mobilePhone`, `otherMails`
- `onPremisesImmutableId`
- `passwordProfile`
- `userPrincipalName`
- delete and restore

For app-only calls, "in addition to Microsoft Graph permissions, the app must be assigned a higher privileged administrator role" whenever the *target* holds a role [src] `user-update`, `user-delete`, `directory-deleteditems-restore`. Which role is enough depends on the target's role [src] `resources/users`, "Who can perform sensitive actions" and "Who can reset passwords":

| Target user holds… | User Admin is enough? | Needs Privileged Auth Admin |
|---|---|---|
| no admin role, Directory Readers, Guest Inviter, Password Admin, Helpdesk Admin, Groups Admin, User Admin, Reports Reader, Message Center Reader, Usage Summary Reports Reader | ✅ | |
| Auth Admin, Global Admin, Privileged Auth Admin, Privileged Role Admin, **any custom role**, membership/ownership of a **role-assignable group**, a role scoped to a **restricted-management AU** | | ✅ |

Recommended assignments for the app's service principal:

- **Writes off:** no directory role.
- **User lifecycle writes:** **User Administrator**. It is also the floor for *any* `passwordProfile` write.
- **Writes on admins as well** (break-glass resets and similar): **Privileged Authentication Administrator**. This role is near-Global-Admin in power, so make it an explicit operator opt-in and never a default.
- **Role-assignable group membership:** `RoleManagement.ReadWrite.Directory` alone [src] `group-post-members`. The "Privileged Role Administrator" note on that page applies to delegated callers.

Assign roles to the service principal with `POST /roleManagement/directory/roleAssignments`, using `principalId` = SP object id and `directoryScopeId` = `/` [src] `rbacapplication-post-roleassignments`.

## What Graph returns when something is missing

| Cause | Status | Body | Confidence |
|---|---|---|---|
| Missing application permission (directory APIs) | 403 | `error.code` = `Authorization_RequestDenied`, message "Insufficient privileges to complete the operation." | [2nd]; `graph/errors` only says 403 means "does not have enough permission or does not have a required license" [src] |
| Missing `AuditLog.Read.All` on `/auditLogs/*` | 403 | `Authentication_MSGraphPermissionMissing` ("Calling principal does not have required MSGraph permissions …") | [unverified] |
| No P1 for sign-in logs, `signInActivity` or registration details | 403 | `error.code` = `Authentication_RequestFromNonPremiumTenantOrB2CTenant`, message "Neither tenant is B2C or tenant doesn't have premium license" | [src] message text in `howto-analyze-activity-logs-with-microsoft-graph`; code [2nd] |
| No P2 for riskyUsers or riskDetections | 403 | Code not documented | [unverified] |
| No Intune licence on `/deviceManagement/*` | 403 or 400 | Code not documented | [unverified] |
| No P2 for `roleEligibilitySchedules` | 4xx | Code not documented | [unverified] |
| Has the permission but lacks a directory role for a sensitive write | 403 | `Authorization_RequestDenied` | [2nd]. Same body as a missing permission, so tell them apart via the `roles` claim. |
| Conditional Access blocks the workload identity | 403 | `insufficient_claims` | [src] `graph/errors` |
| Token for the wrong audience | 403 | | [src] `graph/resolve-auth-errors` |

Two quirks:

- `signin-list` notes that `appliedConditionalAccessPolicies` is **silently omitted** without `Policy.Read.All`. Neither a 403 nor the response marks the omission.
- Free tenants keep audit and sign-in data for 7 days. A 30-day `$filter` just returns less data, with no error [src] `reference-reports-data-retention`.

## Probe design (feeds "Startup probe" in the map)

The falcon-mcp research ([falcon-auth-and-scopes.md](https://github.com/lcleveland/falcon-mcp/blob/main/docs/research/falcon-auth-and-scopes.md)) had no permissions oracle and fell back to per-group read probes. Graph is better off: there are three cheap oracles.

1. **Granted permissions: the token's `roles` claim.** For client-credentials tokens, `roles` holds the granted application permissions (app roles) [src] `entra/identity-platform/access-token-claims-reference`. Decode the JWT payload without validating it; the server already holds the token.
   - Caveat: Learn says clients "should treat [access tokens] as opaque strings" and that Graph tokens have a "proprietary format" [src] `entra/identity-platform/access-tokens`.
   - Caveat: `roles` is "not … an exhaustive list of permissions granted"; directory roles grant access too [src] claims reference.
   - So use `roles` to **show** a group, and never treat its absence as proof the group is denied.
   - The formal alternative is `GET /servicePrincipals(appId='{client-id}')/appRoleAssignments`. It needs `Application.Read.All` [src] `serviceprincipal-list-approleassignments`, which is more than the server otherwise asks for.
2. **Licences: `GET /subscribedSkus?$select=skuPartNumber,capabilityStatus,servicePlans`** with `LicenseAssignment.Read.All`. The devices & licensing job needs this anyway. A feature is present when some SKU has `capabilityStatus` `Enabled` or `Warning` and contains the plan with `provisioningStatus` `Success` [src] `resources/subscribedsku`, `resources/serviceplaninfo`. Plan names are listed in [src] `entra/identity/users/licensing-service-plan-reference`:

   | Feature | `servicePlanName` | Plan id |
   |---|---|---|
   | P1 | `AAD_PREMIUM` | `41781fb2-bc02-4b7c-bd55-b576c07bb09d` |
   | P2 | `AAD_PREMIUM_P2` | `eec0eb4f-6444-4f95-aba0-50c24d67f998` |
   | Intune | `INTUNE_A` | `c1ec4a95-1f05-45b3-a911-aa3fa01094f5` |
   | Workload ID Premium | `AAD_WRKLDID_P2` | `7dc0e92d-bf15-401d-907e-0884efe7c760` |

   Match on plan **id**, not SKU: P1 and P2 ride inside many bundles (M365 E3/E5, Business Premium, EMS). Note that Free tenants that lose P1 still keep their CA policies in a read-and-delete-only state [src] CA overview.
3. **Directory roles: `GET /roleManagement/directory/roleAssignments?$filter=principalId eq '{sp-oid}'&$select=roleDefinitionId`** with `RoleManagement.Read.Directory`. Take the SP's object id from the token's `oid` claim. Map `roleDefinitionId` (the built-in template GUID) to User Admin / Privileged Auth Admin and expose it in `entra_status`.
   - Don't hide sensitive write actions on this basis: the role needed depends on the *target*, so the server only knows at call time.
   - When a sensitive write gets 403 and the SP lacks the role, say so in the error.
4. **Fallback when step 1 or 2 is unavailable:** one `$top=1` GET per tool group. Use the same rules as falcon-mcp:
   - 2xx or 404 means visible.
   - 403 with `Authentication_RequestFromNonPremiumTenantOrB2CTenant` means hidden, reason "licence".
   - Any other 403 means hidden, reason "permission".
   - 429, 5xx or a timeout means visible, with a warning.
   - The P2 and Intune 403 codes are **[unverified]**, so that 403 path reports "permission or licence".
5. **Writes** can't be safely probed. Show a write action when its capability is enabled *and* its permission is in `roles` (when known). Let the call-time 403 explain the rest.

Cheap read probe per group, all `$top=1`:

| Group | Probe |
|---|---|
| users | `GET /users` |
| groups | `GET /groups` |
| devices | `GET /devices` |
| audit | `GET /auditLogs/directoryAudits` |
| sign-ins | `GET /auditLogs/signIns` |
| risk | `GET /identityProtection/riskyUsers` |
| roles | `GET /roleManagement/directory/roleDefinitions` |
| PIM | `GET /roleManagement/directory/roleEligibilitySchedules` |
| CA | `GET /identity/conditionalAccess/policies` |
| auth-methods policy | `GET /policies/authenticationMethodsPolicy` |
| Intune | `GET /deviceManagement/managedDevices` |
| licensing | `GET /subscribedSkus` |

## Suggested permission bundles

| Bundle | Application permissions |
|---|---|
| Read-only, all v1 jobs | `User.Read.All`, `GroupMember.Read.All`, `Directory.Read.All` (memberOf), `Device.Read.All`, `AuditLog.Read.All`, `UserAuthenticationMethod.Read.All`, `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All`, `RoleManagement.Read.Directory`, `RoleEligibilitySchedule.Read.Directory`, `Application.Read.All`, `Policy.Read.All`, `Policy.Read.AuthenticationMethod`, `Policy.Read.DeviceConfiguration`, `Organization.Read.All`, `LicenseAssignment.Read.All`, `BitlockerKey.ReadBasic.All`, `DeviceManagementManagedDevices.Read.All` |
| + lifecycle writes | `User.Create`, `User.ReadWrite.All`, `User.EnableDisableAccount.All`, `User-PasswordProfile.ReadWrite.All`, `User.RevokeSessions.All`, `User.DeleteRestore.All`, `GroupMember.ReadWrite.All`, `Group.Create`, `UserAuthMethod-TAP.ReadWrite.All` + **User Administrator** role |
| + security writes | `IdentityRiskyUser.ReadWrite.All`, `UserAuthenticationMethod.ReadWrite.All` |
| + policy writes | `Policy.ReadWrite.ConditionalAccess` |
| + device/licence writes | `Device.ReadWrite.All`, `LicenseAssignment.ReadWrite.All`, `DeviceManagementManagedDevices.PrivilegedOperations.All` |
| Opt-in, dangerous | `RoleManagement.ReadWrite.Directory`, `BitlockerKey.Read.All`, **Privileged Authentication Administrator** role |

Notes on the bundles:

- `Directory.Read.All` is in the read bundle only because `user-list-memberof` names it as the least privileged permission. Drop it if `GroupMember.Read.All` turns out to cover `memberOf` in practice **[unverified]**.
- Licence-gated permissions are harmless to grant on an unlicensed tenant. The probe hides those groups.
