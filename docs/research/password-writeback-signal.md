# Password-writeback signal

Research for #18 (part of map #1, follow-up to [hybrid-sync.md §5](hybrid-sync.md#5-password-writeback-and-sspr)). Planning only. All facts are from Microsoft Learn pages as read on 2026-10-08; each claim links its source. Placeholders only, nothing about any real directory.

## Answer in brief

- **There is no reliable, documented, app-only, read-only signal for "password writeback is on".** Not in Graph v1.0, not in beta, and not on the AD side.
- The obvious flag, `onPremisesDirectorySynchronization.features.passwordWritebackEnabled`, is documented as "**isn't in use and updating it isn't supported**". It can be read but means nothing.
- Writeback is on only when **two switches** are both on, and neither is exposed in documented Graph:
  1. **Client side.** For Connect Sync, the "Password writeback" optional feature in the wizard on the sync server. For Cloud Sync, `Set-AADCloudSyncPasswordWritebackConfiguration` on the agent server, or the portal checkbox.
  2. **Tenant side.** The SSPR "On-premises integration" toggle in the Entra admin center: "Write back passwords to your on-premises directory", plus "Write back passwords with Microsoft Entra Connect cloud sync" for Cloud Sync.
- **Least-bad option:** read the Entra **directory audit log** (v1.0, `AuditLog.Read.All`, app-only, any licence) for the activities `Enable password writeback for directory` / `Disable password writeback for directory`. The newest such event tells you the current state, but only if it falls inside retention (7 days on Free, 30 on P1/P2). Outside that window, report **"unknown"**, not "off".
- **The only certain test is the operation itself.** An admin `resetPassword` on a synced user either writes back (and succeeds) or fails. That is a write, delegated-only, so it can't serve as a probe. The server should treat the outcome of a real reset as the truth and surface a writeback failure clearly.

## 1. Candidate signals

| Signal | Where | Version | Permission (app-only) | Covers | Trust |
|---|---|---|---|---|---|
| `features.passwordWritebackEnabled` | `GET /directory/onPremisesSynchronization` | v1.0 | `OnPremDirectorySynchronization.Read.All` | Neither | **None.** Documented as not in use ([feature resource](https://learn.microsoft.com/en-us/graph/api/resources/onpremisesdirectorysynchronizationfeature?view=graph-rest-1.0); [Connect tutorial](https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-sspr-writeback#enable-password-writeback-in-microsoft-entra-connect)) |
| Audit activities `Enable password writeback for directory` / `Disable password writeback for directory` | `GET /auditLogs/directoryAudits` | v1.0 | `AuditLog.Read.All` | Both (tenant-side toggle) | **Partial.** Correct when present; silent outside retention ([audit activities](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities#self-service-password-management); [directoryAudit list](https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0); [retention](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention)) |
| SSPR / authentication-methods policy | `GET /policies/authenticationMethodsPolicy` | v1.0 and beta | `Policy.Read.All` | Neither | **None.** No writeback or on-premises property, in either version ([resource, beta](https://learn.microsoft.com/en-us/graph/api/resources/authenticationmethodspolicy?view=graph-rest-beta)) |
| Cloud Sync job / schema / secrets | `servicePrincipals/{id}/synchronization/jobs`, `…/secrets` | beta (as documented for Cloud Sync) | `Synchronization.Read.All` | Cloud Sync | **None documented.** The Graph how-to covers PHS, Exchange hybrid writeback and accidental deletes, but not password writeback. Writeback is turned on through the agent cmdlet or the portal instead ([configure via Graph](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/how-to-inbound-synch-ms-graph); [Cloud Sync tutorial](https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-cloud-sync-sspr-writeback)) |
| AD ACEs for the connector account (Reset password, write `lockoutTime` / `pwdLastSet`, Unexpire Password) | AD over LDAP (`nTSecurityDescriptor`) | n/a | AD read of security descriptors | Both | **Necessary, not sufficient.** See §3 |
| PasswordResetService events 31004/31005 (onboarding), 31015 (service started), 31019 (heartbeat) | Application event log on the Connect Sync server | n/a | Local admin on the sync server | Connect Sync | **High**, but not reachable from the server's Graph or LDAP connections ([troubleshoot writeback](https://learn.microsoft.com/en-us/entra/identity/authentication/troubleshoot-sspr-writeback#if-the-source-of-the-event-is-passwordresetservice)) |
| Outcome of an admin `resetPassword` on a synced user | `POST …/resetPassword` | v1.0 | **Delegated only** (`UserAuthenticationMethod.ReadWrite.All`) | Both | **Definitive** for that user, but it is a write ([resetPassword](https://learn.microsoft.com/en-us/graph/api/authenticationmethod-resetpassword?view=graph-rest-1.0)) |

## 2. Connect Sync vs Cloud Sync

- **Connect Sync.** Writeback is enabled in the Connect wizard ("Optional features" > "Password writeback"). The tenant SSPR toggle "Write back passwords to your on-premises directory" is then set in the admin center. The Connect tutorial says explicitly that updating `PasswordWritebackEnabled` in the service features "isn't supported because this feature flag isn't in use" ([tutorial](https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-sspr-writeback)). Once it's on, the on-prem PasswordResetService onboards (events 31004/31005), listens on Service Bus relays and sends a heartbeat every five minutes (32015 logs a heartbeat failure). None of this is surfaced in documented Graph ([troubleshoot](https://learn.microsoft.com/en-us/entra/identity/authentication/troubleshoot-sspr-writeback)).
- **Cloud Sync.** Writeback needs agent ≥ 1.1.977.0. It is enabled with `Set-AADCloudSyncPasswordWritebackConfiguration -Enable $true` on an agent server, or in the admin center under Password reset > On-premises integration ("Enable password write back for synced users", then optionally "Write back passwords with Microsoft Entra Connect cloud sync") ([Cloud Sync tutorial](https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-cloud-sync-sspr-writeback)). If both clients serve the same domain, Cloud Sync handles writeback ([SSPR writeback](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-writeback)). The Cloud Sync Graph surface (`synchronization/jobs`, `schema`, `secrets`) has no documented writeback key.
- **Both.** The two are told apart only by the extra Cloud Sync checkbox on the same portal blade. The audit log activities are named per directory, not per client, so the log can't say which client does the writeback.

## 3. AD-side markers

- **Connect Sync** needs Reset password, Change password, write `lockoutTime`, write `pwdLastSet` on descendant user objects, and the "Unexpire Password" extended right on each domain root ([tutorial](https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-sspr-writeback#configure-account-permissions-for-microsoft-entra-connect)).
- **Cloud Sync** grants its gMSA Reset password, write `lockoutTime`, write `pwdLastSet` and Unexpire Password **by default**. They can be re-applied with `Set-AADCloudSyncPermissions -PermissionType PasswordWriteBack` ([Cloud Sync tutorial](https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-cloud-sync-sspr-writeback#troubleshooting)).
- **Why they don't prove anything.** Connect Sync's *express* install gives the `MSOL_` connector account Reset password as "Preparation for enabling password writeback", whether or not writeback is ever turned on ([accounts and permissions](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions#ad-ds-connector-account-required-permissions-for-express-settings)). Cloud Sync's gMSA has the rights by default. Helpdesk delegations grant the same extended rights too. So an ACE shows that writeback *could* work, not that it is on. The reverse does hold: if the rights are missing, writeback will fail for the affected users even when it is "enabled".

## 4. Recommendation for the server

1. Don't read `features.passwordWritebackEnabled` at all, or read it only to show it is unused.
2. Expose writeback as a tri-state **`enabled` / `disabled` / `unknown`**, derived from the newest `Enable/Disable password writeback for directory` audit event:
   `GET /v1.0/auditLogs/directoryAudits?$filter=loggedByService eq 'Self-service Password Management' and (activityDisplayName eq 'Enable password writeback for directory' or activityDisplayName eq 'Disable password writeback for directory')&$orderby=activityDateTime desc&$top=1`
   With no hit, return `unknown`. Needs `AuditLog.Read.All`, which is already in the read-only permission set ([entra-permissions-and-licensing.md](entra-permissions-and-licensing.md)).
3. Let an operator override the value in config (e.g. `passwordWriteback: true`) for tenants where the audit window has passed. That is the only way to reach a known state long-term.
4. On a real `resetPassword` of a synced user, report a writeback failure as such. Don't silently fall back to an AD-side reset, because a fallback changes which policy path the password takes.

## Open questions surfaced

- The exact `loggedByService` string and `category` for the two writeback audit activities are taken from the activity reference, not from a live event. Check them against a real event before relying on the filter. The OData `or` in the `$filter` is also unverified for this endpoint.
- Do the audit events fire for the Cloud Sync agent cmdlet, the Connect wizard, or only the portal toggle? The docs don't say which actions emit them.
- Is there an undocumented Graph surface (e.g. beta provisioning-agent listings) that exposes the Cloud Sync writeback setting? Even if there were, it would not meet the "documented" bar, so it is out of scope here.
