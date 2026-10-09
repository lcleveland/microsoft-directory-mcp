# microsoft-directory-mcp

An MCP server for one on-premises Active Directory **forest** and one Entra ID **tenant**, written in Go. It serves over stdio or streamable HTTP and is packaged as a Nix flake with a NixOS module.

- **Each side is optional.** `--ad-forest` turns the AD side on and `--entra-tenant` turns the Entra side on. Set either one or both. A side that is off has no tools.
- **Read-only by default.** Writes are turned on per **capability**. Every write needs a reason, which goes to the audit log, and acts on one target, by id.
- **Some writes never happen:** writes to protected targets (tier-0 AD objects, Entra admins), and a fixed list of dangerous operations that no capability exposes. See [Write capabilities](#write-capabilities).

The AD side speaks LDAP only (LDAPS, or StartTLS), plus DNS for discovery. The Entra side speaks Microsoft Graph v1.0 with an app-only certificate credential.

## Tools

| Group | AD tools | Entra tools |
|---|---|---|
| core (always on) | `ad_status`, `ad_api` (raw LDAP search) | `entra_status`, `entra_api` (raw Graph) |
| identity | `ad_user`, `ad_group`, `ad_ou`, `ad_object` | `entra_user`, `entra_group`, `entra_app` |
| security | | `entra_audit`, `entra_signin`, `entra_risk`, `entra_role` |
| policy | `ad_gpo`, `ad_policy` (password policy and PSOs) | `entra_policy` (read only) |
| devices | `ad_computer` | `entra_device` (Entra and Intune devices), `entra_license` |
| infra | `ad_topology` | `entra_org` |

Each tool takes an `action`, and its description lists the actions and their parameters. A write action exists only while its capability is on. The tags in brackets are licences (see [Licences](#licences)).

| Tool | Read actions | Write actions (capability) |
|---|---|---|
| `ad_status` | connectivity, bind, each domain's PDC emulator, the probe, visible and hidden actions | |
| `ad_user` | search, get, resultant_policy, lockout | disable, enable, unlock, must_change, set_expiry (ad-account-state); reset_password (ad-passwords); create (ad-objects) |
| `ad_group` | search, get, members | add_members, remove_members (ad-group-membership); create (ad-objects) |
| `ad_computer` | search, get | disable, enable, set_expiry (ad-account-state); create (ad-objects) |
| `ad_ou` | search, get, tree | |
| `ad_object` | get, search_deleted | edit, rename, move (ad-objects); delete, restore (ad-delete) |
| `ad_gpo` | search, get, links | link, unlink, block_inheritance (ad-gpo-links) |
| `ad_policy` | domain_default, psos | create, edit, apply, unapply (ad-password-policy) |
| `ad_topology` | domains, trusts, sites, subnets, dcs, fsmo, replication | |
| `ad_api` | search | modify of an allowlisted attribute (ad-objects); add, rename and delete are always refused |
| `entra_status` | token, cloud, sync state, declared writeback, the probe, visible and hidden actions | |
| `entra_user` | search, get, member_of, devices, licenses, auth_methods, registration [P1] | disable, enable, revoke_sessions (entra-account-state); reset_password, issue_tap, delete_auth_method (entra-credentials); create, edit, set_manager, remove_manager (entra-objects); delete, restore (entra-delete); assign_license, remove_license, reprocess_licenses (entra-licenses) |
| `entra_group` | search, get, members, owners | add_members, remove_members (entra-group-membership); create, edit (entra-objects); delete, restore (entra-delete) |
| `entra_device` | search, get, owners, managed_search [Intune], managed_get [Intune] | disable, enable (entra-devices); delete (entra-delete); sync, reboot [Intune] (intune-device-actions); retire, wipe [Intune] (intune-retire-wipe) |
| `entra_api` | get | patch of an allowlisted property (entra-objects); post, put and delete are always refused |
| `entra_audit` | search | |
| `entra_signin` | search [P1] | |
| `entra_risk` | risky_users [P2], risk_detections [P2] | confirm_compromised, dismiss [P2] (entra-risk) |
| `entra_policy` | conditional_access, named_locations, auth_methods_policy, security_defaults | |
| `entra_app` | search_sps, get_sp, search_apps, get_app, expiring_credentials | |
| `entra_role` | definitions, assignments, eligibility [P2] | |
| `entra_license` | skus | |
| `entra_org` | info | |

Searches and lists:
- take a `filter`: an LDAP filter on the AD side and OData on the Entra side. The guides are served as MCP resources at `ad://guide/ldap-filter` and `entra://guide/odata-filter`;
- return a brief field set unless you pass `fields`;
- cap a page at 200 items and 60 KiB, and add a `_truncation` note when they have to cut;
- return `next_cursor` when there is more. Pass it back as `cursor`, with the same arguments.

Graph reads that get a 429 or 503 wait out `Retry-After` and are retried. Writes are never retried, on either side.

## Write capabilities

All are off by default. Turn them on with `--capabilities a,b,...` (or `capabilities` in the NixOS module). A disabled capability's actions are removed from the tool schemas, and the handler refuses them too. Capabilities are used instead of LDAP verbs or Graph scopes because neither of those separates a harmless write from a takeover. See [ADR 0001](docs/adr/0001-write-capability-map.md).

| Capability | Unlocks |
|---|---|
| `ad-account-state` | `ad_user` disable, enable, unlock, must_change, set_expiry; `ad_computer` disable, enable, set_expiry. Only the disable bit of `userAccountControl` is changed. |
| `ad-passwords` | `ad_user` reset_password |
| `ad-group-membership` | `ad_group` add_members, remove_members (up to 20 per call) |
| `ad-objects` | create users, groups and computers; `ad_object` edit, rename, move within a domain; `ad_api` modify of allowlisted attributes |
| `ad-delete` | `ad_object` delete (one leaf object; never a tree delete), restore from the Recycle Bin |
| `ad-gpo-links` | `ad_gpo` link, unlink, block_inheritance |
| `ad-password-policy` | `ad_policy` PSO create, edit, apply, unapply |
| `entra-account-state` | `entra_user` disable, enable, revoke_sessions |
| `entra-credentials` | `entra_user` reset_password, issue_tap (Temporary Access Pass), delete_auth_method |
| `entra-group-membership` | `entra_group` add_members, remove_members (up to 20 per call) |
| `entra-objects` | `entra_user` and `entra_group` create, edit; `entra_user` set_manager, remove_manager |
| `entra-delete` | `entra_user` and `entra_group` delete and restore; `entra_device` delete |
| `entra-licenses` | `entra_user` assign_license, remove_license, reprocess_licenses |
| `entra-devices` | `entra_device` disable, enable |
| `entra-risk` | `entra_risk` confirm_compromised, dismiss |
| `intune-device-actions` | `entra_device` sync, reboot |
| `intune-retire-wipe` | `entra_device` retire, wipe |

### Hard rules

These hold whatever capabilities are on:
- **Protected targets are refused in code.**
  - In AD: `adminCount=1`, RID below 1000, `isCriticalSystemObject`, domain controllers, protected groups and anything nested in them.
  - In Entra: any directory-role holder, and any member or owner of a role-assignable group.
  - For policy: a PSO apply that would reach a protected target, editing a PSO that already applies to one, and GPO link changes on the Domain Controllers OU.
- **One target per write, by id.** There is no bulk mode and no selecting targets by filter. Delete, password reset, and Intune retire and wipe need `confirm` set to the target's name.
- **Every write needs `reason`.** It is audit-logged with the tool, action and target, before the write and again with the outcome. Logs go to stderr.
- **Passwords are generated by the server.** A password is returned once and never logged, and must-change is on by default. The client can't choose a password, so none ever passes through the model's transcript.
- **AD writes go to the PDC emulator** of the target's domain, after a read of the target there. If the server can't reach or bind to the PDC emulator, the write goes to another domain controller, and the result says so (`fallback` and a note).
- **Attribute edits are allowlisted in code.** Only descriptive attributes can be edited: names, title, department, address, phone and the like. Nothing that grants access, delegates, or changes how anyone signs in.
- **Raw tools never bypass these rules.** In `ad_api` and `entra_api`, a write that a first-class action covers is refused and pointed to that action. Any other write is refused unless it is an allowlisted attribute edit.

**Never exposed:**
- **AD:** UAC bits other than disable, SPNs, key credentials, resource-based constrained delegation, `sIDHistory`, ACLs, cross-domain moves, tree delete, AdminSDHolder, `dSHeuristics`, GPO content, schema and configuration, trusts.
- **Entra:** Conditional Access, named locations, the authentication methods policy, security defaults, role assignments and PIM, app and service principal credentials, consent grants, and source-of-authority conversion.

## Hybrid behaviour

With both sides on, the server joins a synced object to its **counterpart** by SID: AD `objectSid` equals Entra `onPremisesSecurityIdentifier`. This works for users, groups and computers. A `get` on either side returns a `counterpart` block that names the other side's object and the object's **source of authority**. The source of authority comes from `onPremisesSyncBehavior.isCloudManaged` where Graph answers it, and from `onPremisesSyncEnabled` otherwise.

Every write checks the source of authority before anything is sent:
- **Entra refuses** synced attributes, enable and disable, delete, and membership of synced groups on synced objects. The error points to the matching `ad_*` action.
- **Entra allows** licences, sessions, authentication methods, risk, and membership of cloud groups on synced users.
- **An Entra password reset** on a synced user needs password writeback declared on (`--entra-password-writeback on`).
- **AD refuses** writes to an object whose counterpart is cloud-managed.
- **Moving an AD object** that has a counterpart returns a warning, not a refusal. The server can't read Connect Sync's OU filter, so it can't tell whether the move takes the object out of sync scope.

**No sync trigger.** Connect Sync has no Graph API to start a cycle, so an AD write reaches Entra on the next scheduled cycle: every 30 minutes by default for Connect Sync, and about every 2 minutes for Cloud Sync. `entra_status` shows whether sync is on and when it last ran.

**Password writeback is operator-declared.** App-only Graph has no reliable way to detect it ([research](docs/research/password-writeback-signal.md)). Set `--entra-password-writeback` to `on`, `off` or `unknown` (the default) to match the Entra admin center: **Password reset → On-premises integration**. `entra_status` reports the value as operator-declared.

## Probe

At startup the server probes each configured side once, before it lists its tools:
- **AD:** it binds, discovers the forest's domains, and runs read probes for rights that are not granted by default, such as reading PSOs.
- **Entra:** it reads the granted application permissions from the token's `roles` claim, the P1 and P2 licences from `subscribedSkus`, and the Intune licence from one read of Intune managed devices.

An action whose permission, licence or AD right is missing is hidden. A tool left with no actions is not listed. Anything the probe can't decide (a timeout, a 5xx) fails open and shows the action.

`ad_status` and `entra_status` report the connection, the probe result, the enabled groups and capabilities, the visible actions, and every hidden action with the reason it is hidden. Call one first when another tool fails. The probe runs once, so restart the server after you grant a right. `--no-probe` skips the probe and shows every action that the groups and capabilities allow.

## Install

The flake provides:
- the package, as `packages.<system>.default`;
- `overlays.default`, which adds `pkgs.microsoft-directory-mcp`;
- `nixosModules.default`.

Run it once without installing:

```sh
nix run github:lcleveland/microsoft-directory-mcp -- --help
```

### NixOS

```nix
{
  inputs.microsoft-directory-mcp.url = "github:lcleveland/microsoft-directory-mcp";

  outputs = { nixpkgs, microsoft-directory-mcp, ... }: {
    nixosConfigurations.host = nixpkgs.lib.nixosSystem {
      modules = [
        microsoft-directory-mcp.nixosModules.default
        {
          services.microsoft-directory-mcp = {
            enable = true; # the HTTP service, and the binary on PATH
            ad = {
              forest = "corp.example.com";
              bindUser = "svc-mcp@corp.example.com";
              # sops-nix / agenix path, or a root-only file:
              bindPasswordFile = "/run/secrets/ad-bind-password";
              caFile = "/run/secrets/corp-ca.pem";
            };
            entra = {
              tenant = "00000000-0000-0000-0000-0000000000aa";
              clientId = "00000000-0000-0000-0000-0000000000bb";
              certFile = "/run/secrets/entra-cert.pem";
              passwordWriteback = "on";
            };
            capabilities = [ "ad-account-state" ];
          };
        }
      ];
    };
  };
}
```

`enable` runs the streamable HTTP systemd service. On a workstation that only spawns the server over stdio from an MCP client, set `installCli = true` and leave `enable` off. That puts the binary on PATH without starting a service.

The module:
- passes the secret files and the CA file through systemd `LoadCredential`, so they never reach the Nix store, argv or the environment;
- refuses secret paths inside the Nix store, and relative paths;
- runs the service as a hardened `DynamicUser`;
- refuses a non-loopback `http.addr` without `http.authTokenFile`;
- warns when `ad.insecureSkipVerify` is on.

| Option | Flag | Default |
|---|---|---|
| `enable` | | off |
| `installCli` | | `enable` |
| `package` | | this flake's build |
| `ad.forest`, `ad.bindUser` | `--ad-forest`, `--ad-bind-user` | unset; both are needed for the AD side |
| `ad.bindPasswordFile` | `--ad-bind-password-file` | required with `ad.forest` |
| `ad.tls` | `--ad-tls` | `ldaps` |
| `ad.caFile` | `--ad-ca-file` | none |
| `ad.insecureSkipVerify` | `--ad-insecure-skip-verify` | `false` |
| `ad.site` | `--ad-site` | none |
| `ad.dcs` | `--ad-dc` | `[ ]` (DNS SRV discovery) |
| `entra.tenant`, `entra.clientId` | `--entra-tenant`, `--entra-client-id` | unset; both are needed for the Entra side |
| `entra.certFile` | `--entra-cert-file` | required with `entra.tenant` |
| `entra.cloud` | `--entra-cloud` | `global` |
| `entra.passwordWriteback` | `--entra-password-writeback` | `unknown` |
| `entra.loginUrl`, `entra.graphUrl` | `--entra-login-url`, `--entra-graph-url` | none (tests only) |
| `toolGroups` | `--tool-groups` | all |
| `capabilities` | `--capabilities` | `[ ]` |
| `noProbe` | `--no-probe` | `false` |
| `requestTimeout` | `--request-timeout` | `30s` |
| `logLevel` | `--log-level` | `info` |
| `http.addr`, `http.path` | `--addr`, `--path` | `127.0.0.1:8235`, `/mcp` |
| `http.authTokenFile` | `--http-auth-token-file` | none; required for a non-loopback `addr` |
| `extraArgs` | | `[ ]`; never put a secret here |

### Claude Code

Over HTTP, against the NixOS service:

```sh
claude mcp add --scope user --transport http directory http://127.0.0.1:8235/mcp
```

With a bearer token, add `--header "Authorization: Bearer <token>"`.

Over stdio:

```sh
claude mcp add directory -- microsoft-directory-mcp \
  --ad-forest corp.example.com --ad-bind-user svc-mcp@corp.example.com \
  --ad-bind-password-file $HOME/.config/microsoft-directory-mcp/ad-bind-password
```

## Configuration

Each flag marked with an env var can also be set through `MSDIR_` plus the flag name, upper-cased with `_` for `-`. A flag on the command line wins over its env var.

| Flag | Env | Default |
|---|---|---|
| `--ad-forest` | `MSDIR_AD_FOREST` | unset; it turns the AD side on |
| `--ad-bind-user` | `MSDIR_AD_BIND_USER` | required with `--ad-forest`; a UPN |
| `--ad-bind-password-file` | `MSDIR_AD_BIND_PASSWORD_FILE` | required with `--ad-forest` |
| `--ad-tls` (`ldaps`, `starttls`) | `MSDIR_AD_TLS` | `ldaps`. Plain LDAP is never used. |
| `--ad-ca-file` | `MSDIR_AD_CA_FILE` | none; a PEM bundle added to the system roots |
| `--ad-insecure-skip-verify` | | off; logs a warning when on |
| `--ad-site` | `MSDIR_AD_SITE` | none; discovery then uses the site's SRV records |
| `--ad-dc` | `MSDIR_AD_DC` | DNS SRV; a comma-separated `host` or `host:port` list |
| `--entra-tenant` | `MSDIR_ENTRA_TENANT` | unset; a tenant ID or domain, and it turns the Entra side on |
| `--entra-client-id` | `MSDIR_ENTRA_CLIENT_ID` | required with `--entra-tenant` |
| `--entra-cert-file` | `MSDIR_ENTRA_CERT_FILE` | required with `--entra-tenant` |
| `--entra-cloud` (`global`, `usgov`, `usgovdod`, `china`) | `MSDIR_ENTRA_CLOUD` | `global` |
| `--entra-password-writeback` (`on`, `off`, `unknown`) | `MSDIR_ENTRA_PASSWORD_WRITEBACK` | `unknown` |
| `--entra-login-url`, `--entra-graph-url` | `MSDIR_ENTRA_LOGIN_URL`, `MSDIR_ENTRA_GRAPH_URL` | the cloud's; for tests. They must be https unless the host is loopback, and work with `global` only. |
| `--tool-groups` (`core`, `identity`, `security`, `policy`, `devices`, `infra`) | `MSDIR_TOOL_GROUPS` | all; `core` is always on |
| `--capabilities` | `MSDIR_CAPABILITIES` | none |
| `--no-probe` | | probe on |
| `--request-timeout` | | `30s` |
| `--log-level` (`debug`, `info`, `warn`, `error`) | `MSDIR_LOG_LEVEL` | `info` |
| `--stdio` / `--http` | | stdio |
| `--addr`, `--path` | | `127.0.0.1:8235`, `/mcp` |
| `--http-auth-token-file` | `MSDIR_HTTP_AUTH_TOKEN_FILE` | none; a non-loopback `--addr` requires it |
| `--version` | | |

Secrets (the bind password, the Entra key, and the HTTP bearer token) are read only from files. There is no flag or env var that takes a secret's value, because argv and the environment are readable under `/proc`. Surrounding whitespace in a secret file is trimmed.

Over HTTP, clients send the token as `Authorization: Bearer <token>`. `/healthz` stays open.

## AD setup

### Service account

1. Create a plain user for the server, for example `svc-mcp@corp.example.com`. Put it in no admin group. Being a member of Domain Users is enough for every read except the ones listed under [Read rights](#read-rights).
2. Give it a long random password, and set the password never to expire, or rotate it on a schedule.
3. Put the password in a file only you can read. Paste it into `cat`, so it stays out of argv and shell history, then press Ctrl-D:
   ```sh
   mkdir -p ~/.config/microsoft-directory-mcp
   (umask 077; cat > ~/.config/microsoft-directory-mcp/ad-bind-password)
   ```
   For the NixOS service, use a root-only file or a sops-nix or agenix path instead.
4. Grant the write rights below only for the capabilities you will turn on.
5. Call `ad_status`. It tells an unreachable domain controller, a TLS failure and a rejected bind apart, and lists hidden actions with the missing right.

### TLS

The server binds over TLS only:
- **LDAPS** (`--ad-tls ldaps`, the default) uses 636 for a domain controller and 3269 for the global catalog.
- **StartTLS** (`--ad-tls starttls`) uses 389 and 3268.

An explicit port in `--ad-dc` is kept. Domain controllers are found through DNS SRV records, narrowed to `--ad-site` when one is set, unless `--ad-dc` lists them.

Domain controller certificates are usually issued by an enterprise CA that the host doesn't trust. Pass that CA with `--ad-ca-file` rather than `--ad-insecure-skip-verify`. With verification off, the bind password can go to an impostor.

Every enterprise root CA is published in the `cACertificate` attribute of its object under `CN=Certification Authorities,CN=Public Key Services,CN=Services` in the Configuration partition. To export it from a domain-joined Windows machine:

```powershell
$cfg = ([ADSI]"LDAP://RootDSE").configurationNamingContext
$s = [ADSISearcher]"(objectClass=certificationAuthority)"
$s.SearchRoot = [ADSI]"LDAP://CN=Certification Authorities,CN=Public Key Services,CN=Services,$cfg"
$s.PropertiesToLoad.AddRange(@("cn", "cACertificate"))
$s.FindAll() | ForEach-Object {
  [IO.File]::WriteAllBytes("$PWD\$($_.Properties.cn[0]).cer", $_.Properties.cacertificate[0])
}
```

Then convert each certificate to PEM and concatenate them into one bundle:

```sh
openssl x509 -inform der -in "Example Root CA.cer" -out corp-ca.pem
```

Compare the certificate's fingerprint (`openssl x509 -noout -fingerprint -sha256 -in corp-ca.pem`) with the one the CA shows before you trust it.

### Read rights

Domain Users can read almost everything the read tools ask for. Two areas need delegation:
- **PSOs** (`ad_policy psos`, `ad_user resultant_policy`, and every `ad_policy` write): grant Read on the Password Settings Container and its PSOs:
  ```
  dsacls "CN=Password Settings Container,CN=System,DC=corp,DC=example,DC=com" /I:T /G "CORP\svc-mcp:GR"
  ```
- **Deleted objects** (`ad_object search_deleted`): by default only administrators can list the Deleted Objects container. A Domain Admin can grant the right with:
  ```
  dsacls "CN=Deleted Objects,DC=corp,DC=example,DC=com" /takeownership
  dsacls "CN=Deleted Objects,DC=corp,DC=example,DC=com" /G "CORP\svc-mcp:LCRP"
  ```

Repeat both for each domain in the forest.

### Write rights: delegate per attribute

Delegate on the OUs that hold the objects you want the server to manage, never on the domain root. Delegate **per attribute**. Do not use the "Account Restrictions" property set: on Server 2012 and later it also covers `msDS-AllowedToActOnBehalfOfOtherIdentity`, so it would let the account set up resource-based constrained delegation, which is a known takeover path.

`/I:S` applies a grant to the objects below the OU. The last field names the object class the grant applies to. Run each command on every OU in scope:

| Capability | Rights on the OU (`dsacls "OU=Staff,DC=corp,DC=example,DC=com" ...`) |
|---|---|
| `ad-account-state` | `/I:S /G "CORP\svc-mcp:WP;userAccountControl;user" "CORP\svc-mcp:WP;lockoutTime;user" "CORP\svc-mcp:WP;pwdLastSet;user" "CORP\svc-mcp:WP;accountExpires;user"`, and the `userAccountControl` and `accountExpires` grants again for `computer` |
| `ad-passwords` | `/I:S /G "CORP\svc-mcp:CA;Reset Password;user" "CORP\svc-mcp:WP;pwdLastSet;user"` |
| `ad-group-membership` | `/I:S /G "CORP\svc-mcp:WP;member;group"` |
| `ad-objects` | create: `/G "CORP\svc-mcp:CC;user" "CORP\svc-mcp:CC;group" "CORP\svc-mcp:CC;computer"`. Edit: `/I:S` with `WP;<attribute>;<class>` for each allowlisted attribute you want editable. Rename: `WP;cn` and `WP;name`. Move: Delete Child (`DC;<class>`) on the source OU and Create Child on the target. |
| `ad-delete` | delete: `/G "CORP\svc-mcp:DC;user" "CORP\svc-mcp:DC;group" "CORP\svc-mcp:DC;computer"`. Restore also needs the `Reanimate Tombstones` right on the domain: `dsacls "DC=corp,DC=example,DC=com" /G "CORP\svc-mcp:CA;Reanimate Tombstones"`, plus Create Child on the target OU. |
| `ad-gpo-links` | `/I:T /G "CORP\svc-mcp:WP;gPLink" "CORP\svc-mcp:WP;gPOptions"` |
| `ad-password-policy` | on the Password Settings Container: `/G "CORP\svc-mcp:CC;msDS-PasswordSettings"` to create, and `/I:S /G "CORP\svc-mcp:WP;;msDS-PasswordSettings"` to edit, apply and unapply |

`ad-account-state` must-change and `ad-passwords` both write `pwdLastSet`. A password reset sets must-change by default.

Protected objects (with `adminCount=1`) don't inherit OU delegation, because AdminSDHolder resets their ACL. The server refuses them anyway, whatever the account's rights.

## Entra setup

### App registration

1. In the Entra admin center, go to **App registrations → New registration**. Choose single tenant and no redirect URI.
2. Create a certificate and key, and keep the key in a file only you can read:
   ```sh
   cd ~/.config/microsoft-directory-mcp
   (umask 077
    openssl req -x509 -newkey rsa:3072 -sha256 -days 365 -nodes \
      -subj "/CN=microsoft-directory-mcp" -keyout key.pem -out cert.pem
    cat key.pem cert.pem > entra-cert.pem && rm key.pem)
   ```
   The key must be an unencrypted RSA key, PKCS#8 or PKCS#1. `--entra-cert-file` takes the key and the certificate together in one PEM file.
3. Upload `cert.pem` under **Certificates & secrets → Certificates**. Don't add a client secret: the server doesn't use one.
4. Under **API permissions**, add Microsoft Graph **application** permissions (not delegated). Start with the read list below and add only the write permissions you need. Then **Grant admin consent**.
5. Note the **Application (client) ID** for `--entra-client-id`, and the **Directory (tenant) ID** (or a verified domain) for `--entra-tenant`.
6. Call `entra_status`. It tells a rejected certificate apart from a missing permission, and lists the hidden actions with the permission or licence each is missing. After granting a permission, restart the server: the probe runs only at startup.

To rotate the certificate, upload the new one, replace the file, restart the server, then remove the old certificate from the app.

### Read permissions

Each action needs any one of the permissions it accepts. This list covers every read with the least privilege:

| Permission | Used by |
|---|---|
| `User.Read.All` | `entra_user` search, get, licenses |
| `GroupMember.Read.All` | `entra_group` reads, `entra_user member_of` |
| `Device.Read.All` | `entra_device` search, get, owners; `entra_user devices` |
| `DeviceManagementManagedDevices.Read.All` | `entra_device` managed_search, managed_get [Intune] |
| `UserAuthenticationMethod.Read.All` | `entra_user auth_methods` |
| `AuditLog.Read.All` | `entra_audit`, `entra_signin` [P1], `entra_user registration` [P1], and `signInActivity` on user gets [P1] |
| `IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All` | `entra_risk` reads [P2] |
| `Policy.Read.All`, `Policy.Read.AuthenticationMethod` | `entra_policy` |
| `Application.Read.All` | `entra_app` |
| `RoleManagement.Read.Directory` | `entra_role` definitions, assignments, eligibility [P2]; the protected-target check before every user write |
| `LicenseAssignment.Read.All` | `entra_license skus`; the probe's licence check |
| `Organization.Read.All` | `entra_org`, `entra_status` |

`entra_api get` can reach any v1.0 path, but only within what these permissions allow.

### Write permissions and the directory role

| Capability | Application permissions |
|---|---|
| `entra-account-state` | `User.EnableDisableAccount.All`, `User.RevokeSessions.All` |
| `entra-credentials` | `User-PasswordProfile.ReadWrite.All` (reset_password), `UserAuthMethod-TAP.ReadWrite.All` (issue_tap), `UserAuthenticationMethod.ReadWrite.All` (delete_auth_method) |
| `entra-group-membership` | `GroupMember.ReadWrite.All` |
| `entra-objects` | `User.ReadWrite.All`; `Group.Create` to create groups; `Group.ReadWrite.All` to edit them |
| `entra-delete` | `User.DeleteRestore.All`, `Group.ReadWrite.All`, `Device.ReadWrite.All` |
| `entra-licenses` | `LicenseAssignment.ReadWrite.All` |
| `entra-devices` | `Device.ReadWrite.All` |
| `entra-risk` | `IdentityRiskyUser.ReadWrite.All` |
| `intune-device-actions`, `intune-retire-wipe` | `DeviceManagementManagedDevices.PrivilegedOperations.All` |

**Directory role: User Administrator at most.** For app-only calls, Graph requires a directory role on the service principal for sensitive writes, on top of the permission. Password reset needs User Administrator for any target. Assign User Administrator to the app's service principal only when `entra-credentials` is on. Every other write needs no role, because it only ever targets non-admins.

Never assign Privileged Authentication Administrator. That role exists to act on admins, and the server refuses admins as targets.

### Licences

| Licence | Needed for |
|---|---|
| Entra ID Free | everything not listed below; directory audit keeps 7 days of data |
| Entra ID P1 | sign-in logs, `signInActivity`, the registration report; audit keeps 30 days of data |
| Entra ID P2 | `entra_risk` (reads and writes), PIM eligibility |
| Intune | `managed_search`, `managed_get`, and the sync, reboot, retire and wipe actions |

Granting a permission whose licence the tenant lacks is harmless: the probe finds the licence missing and hides the actions.

## Out of scope

- **GPO settings.** They live in SYSVOL, which would need SMB. `ad_gpo` reports GPO objects and links, and returns `gPCFileSysPath` so you can open the settings in GPMC. See [ADR 0003](docs/adr/0003-ldap-only-ad-transport.md).
- **Which machine caused a lockout (event 4740).** Reading it would need WinRM or EventLog RPC on the domain controllers. `ad_user lockout` reports the LDAP facts instead: `lockoutTime`, the originating domain controller, and `badPwdCount` per domain controller. See [ADR 0003](docs/adr/0003-ldap-only-ad-transport.md).
- **Bulk writes and filter-selected targets.** The client loops instead. See [ADR 0001](docs/adr/0001-write-capability-map.md).
- **Triggering a sync cycle**, and anything in the [never exposed](#hard-rules) list.
- **The Graph SDK.** The Entra side uses a small stdlib client, partly because the SDK would retry writes. See [ADR 0002](docs/adr/0002-hand-rolled-graph-client.md).

## Development

```sh
nix develop            # go and tools
go test ./...
nix flake check        # package build and Go tests, module eval checks, VM test
nix build .#checks.x86_64-linux.vm   # the VM test alone: a Samba AD DC and a stub Graph
```

The design decisions are recorded on [the map issue](https://github.com/lcleveland/microsoft-directory-mcp/issues/1) and in [`docs/adr/`](docs/adr/). Research notes are in [`docs/research/`](docs/research/). Terms are defined in [`GLOSSARY.md`](GLOSSARY.md).
