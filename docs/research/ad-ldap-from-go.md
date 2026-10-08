# Active Directory over LDAP from Go on Linux

Research for [#2](https://github.com/lcleveland/microsoft-directory-mcp/issues/2) (part of map #1). Question: what does a Go process on a **non-domain-joined Linux host** need to read and write a **forest** over LDAP? Sources are primary (Microsoft Learn / open specifications, library source and release notes) and were read on 2026-10-08. All names below are placeholders (`example.com`, `corp.example.com`).

## Answer in brief

- **Library:** `github.com/go-ldap/ldap/v3` is the only serious choice and is healthy (v3.4.15, 2026-10-07; Go 1.26 module). It covers bind, search, paging, modify, password modify, and the Microsoft controls we need. It does **not** follow referrals, do range retrieval, or wrap SASL traffic (no signing/sealing). Kerberos goes through its `gssapi` subpackage over `gokrb5/v8`.
- **Transport:** always TLS: LDAPS on 636 (3269 for the Global Catalog) or StartTLS on 389/3268. go-ldap has no SASL security layer, so a bind over plain 389 is rejected wherever LDAP signing is required. New Windows Server 2025 forests require it by default.
- **Bind:** use **simple bind over TLS** as the baseline. It is the only password-based bind from Linux that survives *every* signing and channel-binding setting, because channel binding never applies to simple binds. Kerberos (gokrb5 keytab) over TLS works too, except where channel binding is set to **Always**: on Linux neither gokrb5 nor go-ntlmssp sends a channel-binding token. Treat NTLM as unsupported.
- **Discovery:** DNS SRV (`_ldap._tcp.dc._msdcs.<domain>`, site-scoped `_ldap._tcp.<site>._sites.dc._msdcs.<domain>`, `_gc._tcp.<forest>`). SRV records advertise only 389/3268, so the client maps them to 636/3269 itself. Site awareness comes from an "LDAP ping" (rootDSE `netlogon` search), which AD answers over TCP as well as UDP. go-ldap can send it, and we decode the response ourselves.
- **Forest-wide:** read through the GC (3268/3269, partial attribute set, read-only). Write to a domain controller of the domain that owns the object, chosen from `crossRef` objects in `CN=Partitions`. Keep one connection per domain and never chase referrals.
- **v1 jobs:** sites/DCs, FGPP, GPO objects and links, and most of replication health are reachable over LDAP alone. **GPO settings** (SYSVOL, SMB) and the **lockout caller machine** (Security event 4740, event log RPC/WinRM) are not.

## 1. go-ldap/v3 maturity and surface

| Fact | Source |
| --- | --- |
| Latest v3.4.15 published 2026-10-07; earlier releases v3.4.14 (2026-07), v3.4.13 (2026-03), v3.4.12 (2025-10). Repo active, not archived. | GitHub releases API for go-ldap/ldap |
| `go.mod`: `go 1.26.0`; depends on `Azure/go-ntlmssp v0.1.1`, `jcmturner/gokrb5/v8 v8.4.4`, `alexbrainman/sspi` (Windows only), `go-asn1-ber/asn1-ber`. | [v3/go.mod](https://github.com/go-ldap/ldap/blob/master/v3/go.mod) |
| Bind methods: `SimpleBind`, `Bind`, `UnauthenticatedBind`, `ExternalBind`, `NTLMBind`, `NTLMBindWithHash`, `NTLMChallengeBind`, `GSSAPIBind`, `GSSAPIBindRequest(WithAPOptions)`, `MD5Bind`, `DigestMD5Bind`. `DialURL` (ldap://, ldaps://), `StartTLS(*tls.Config)`. | [pkg.go.dev](https://pkg.go.dev/github.com/go-ldap/ldap/v3) |
| Search: `Search`, `SearchWithPaging(req, size)`, `SearchAsync(ctx, req, buf)`. Writes: `Add`, `Modify`, `ModifyDN`, `Del`, `PasswordModify`, `Extended`. Also `DirSync`, `WhoAmI`. | [pkg.go.dev](https://pkg.go.dev/github.com/go-ldap/ldap/v3) |
| Microsoft controls with OIDs: Paging `1.2.840.113556.1.4.319`, SD flags `.801`, ShowDeleted `.417`, Notification `.528`, ExtendedDN `.529`, DirSync `.841`, ServerLinkTTL `.2309`, SubtreeDelete `.805`, ServerSideSorting `.473`. | [pkg.go.dev](https://pkg.go.dev/github.com/go-ldap/ldap/v3), [v3/control.go](https://github.com/go-ldap/ldap/blob/master/v3/control.go) |
| **Referrals are not followed**: `SearchResult.Referrals []string` is only collected, including across `SearchWithPaging` pages. | [v3/search.go](https://github.com/go-ldap/ldap/blob/master/v3/search.go) |
| `gssapi` package: `NewClientWithKeytab(username, realm, keytabPath, krb5confPath)`, `NewClientWithPassword`, `NewClientFromCCache`, on gokrb5 v8. `SSPIClient` is `//go:build windows`. | [pkg.go.dev gssapi](https://pkg.go.dev/github.com/go-ldap/ldap/v3/gssapi), [v3/gssapi/sspi.go](https://github.com/go-ldap/ldap/blob/master/v3/gssapi/sspi.go) |
| **No SASL security layer**: `NegotiateSaslAuth` comments "We never want a security layer" and sends layer byte 0. `bind.go` says "SASL security layers are not supported currently". After a bind, traffic is neither signed nor sealed. | [v3/gssapi/client.go](https://github.com/go-ldap/ldap/blob/master/v3/gssapi/client.go), [v3/bind.go](https://github.com/go-ldap/ldap/blob/master/v3/bind.go) |
| **Channel binding only on Windows**: v3.4.12 "Add RFC 5929 channel binding support for SSPI client" (PR #565). The gokrb5 GSSAPI path builds its authenticator checksum with a zeroed Bnd field (`newAuthenticatorChksum`). go-ntlmssp defines `avIDMsvChannelBindings` but never sends it, and go-ldap's `NTLMBindRequest` has no CBT field. | [v3.4.12 notes](https://github.com/go-ldap/ldap/releases/tag/v3.4.12), [gokrb5 spnego/krb5Token.go](https://github.com/jcmturner/gokrb5/blob/master/v8/spnego/krb5Token.go), [go-ntlmssp avids.go](https://github.com/Azure/go-ntlmssp/blob/master/avids.go) |
| `gokrb5` last release v8.4.4 (2023-02), last push 2024-07. It works but is dormant. | GitHub API for jcmturner/gokrb5 |

**Gotcha:** `NewControlMicrosoftSDFlags()` returns `ControlValue: 0`, and MS-ADTS treats 0 as "all four parts including the SACL". Always set `ControlValue = 0x7` (owner | group | DACL), as in §5.

## 2. LDAPS vs StartTLS, signing and channel binding

What Microsoft enforces:

- **Signing** applies only to non-TLS SASL sessions. When it is required, the domain controller rejects "SASL LDAP binds that don't request signing" and "simple binds over unencrypted connections". TLS satisfies the integrity requirement: "When you use TLS … LDAP signing doesn't apply separately." ([LDAP signing overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing), [enable LDAP signing](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server))
- **Windows Server 2025 defaults:** new deployments *require* signing ("LDAP server signing requirements enforcement" is enabled by default). Upgrades keep an existing policy, and with no policy set they also require signing. On 2022 and earlier, signing is optional by default. ([LDAP signing overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing))
- **Channel binding (CBT/EPA)** "applies … only to TLS-secured sessions that use SASL authentication". It covers both NTLM and Kerberos SASL binds over TLS. It does **not** apply to simple bind over TLS, certificate (EXTERNAL) bind over TLS, or non-TLS SASL. Policy `LdapEnforceChannelBinding` takes three values: 0 Never; 1 When supported ("Clients that don't support CBT are still allowed"); 2 Always ("rejects authentication from clients that don't provide a valid token"). Windows Server 2025 defaults to **When supported**, and 2022 and earlier default to **Never**. ([LDAP channel binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), [KB4520412](https://support.microsoft.com/en-us/topic/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a))
- **Password writes** (`unicodePwd`) need "a 128-bit SSL/TLS or SASL encrypted connection". An admin reset is a single *replace*. A user change is *delete old + add new*. The value is a quoted UTF-16LE string. ([Set a password with Ldifde](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/set-user-password-with-ldifde)) go-ldap cannot seal, so this needs TLS.

How each bind fares from go-ldap on Linux:

| Bind | Plain 389 | TLS, CBT Never/When supported | TLS, CBT Always | Notes |
| --- | --- | --- | --- | --- |
| Simple (service account DN/UPN + password) | Rejected where signing is required; cleartext password anyway | Works | **Works** (CBT doesn't apply) | Least moving parts; password file via `LoadCredential`. No relay protection, but none is needed for a client that holds the password. |
| GSSAPI/Kerberos (gokrb5, keytab) | Rejected where signing is required (no security layer) | Works | **Fails** (no CBT from gokrb5) | Needs `krb5.conf`, a keytab, an SPN `ldap/<dc-fqdn>` (connect by FQDN, not IP), and a clock within Kerberos skew. |
| NTLM (go-ntlmssp) | Rejected where signing is required | Works | **Fails** (no CBT) | Microsoft calls NTLM deprecated; skip. |
| EXTERNAL (TLS client cert) | n/a | Works if the forest maps the certificate | Works (CBT doesn't apply) | Needs certificate-mapping setup on the AD side. Out of scope unless asked. |

**StartTLS vs LDAPS:** both count as TLS for signing and channel binding ([LDAP signing overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) table: "port 636, or port 389 with STARTTLS"). Both need a domain controller certificate the host trusts, so the AD CA bundle is a config input. LDAPS (`ldaps://`, 636/3269) is simpler: TLS starts before any LDAP traffic and there is no downgrade window. Use LDAPS by default, with StartTLS as a fallback switch.

## 3. Domain controller discovery and site awareness

- A non-RODC domain controller registers `_ldap._tcp.<domain>`, `_ldap._tcp.dc._msdcs.<domain>`, `_kerberos._tcp[.dc._msdcs].<domain>`, and per site `_ldap._tcp.<site>._sites.dc._msdcs.<domain>`. A GC registers `_ldap._tcp.gc._msdcs.<forest>`, `_gc._tcp.<forest>`, and the site-scoped `_gc._tcp.<site>._sites.<forest>`. The PDC emulator registers `_ldap._tcp.pdc._msdcs.<domain>`. SRV ports are **389 (LDAP), 3268 (GC), 88, 464**. LDAPS ports are not advertised. ([MS-ADTS 6.3.2.3 SRV Records](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c1987d42-1847-4cc9-acf7-aab2136d6952)) Go's `net.LookupSRV("ldap","tcp","dc._msdcs.corp.example.com")` covers this with the stdlib.
- **LDAP ping:** a rootDSE search for the `netlogon` attribute with filter `(&(DnsDomain=corp.example.com)(NtVer=…))`. The domain controller answers with a little-endian `NETLOGON_SAM_LOGON_RESPONSE_EX` blob carrying DC flags, the DC's site, and the *client's* site ([MS-ADTS 6.3.3 LDAP Ping](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/895a7744-aff3-4f64-bcfa-f8c05915d2e9), [NETLOGON_SAM_LOGON_RESPONSE_EX](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8401a33f-34a8-40ca-bf03-c3484b66265f)). "Active Directory supports LDAP searches for this attribute via both UDP and TCP/IP" ([MS-ADTS netlogon](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/556d0738-e03e-449a-a771-d0a0b14edf21)), so go-ldap over TCP can do it without CLDAP. The blob decoder is ours to write.
- **Minimal plan:** SRV lookup, try candidates in priority/weight order, run one LDAP ping to learn the client site, then prefer that site's SRV list. A config override (static domain controller list) skips discovery. Site awareness could be deferred: on a single-site forest it buys nothing.

## 4. Global Catalog, per-domain connections, referrals

- A GC listens on 3268 (3269 TLS) and holds a partial, read-only replica of every domain in the forest ([MS-ADTS SRV Records](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c1987d42-1847-4cc9-acf7-aab2136d6952) for ports; the read-only partial replica is per the MS-ADTS glossary "global catalog"). Use it for forest-wide *find* (users, groups, computers by name/UPN/SID). Attributes outside the partial attribute set need a follow-up read against the owning domain.
- **Writes and full reads go to a domain controller of the owning domain.** Map DN suffix → domain from `crossRef` objects under `CN=Partitions,CN=Configuration,…` (`nCName`, `dnsRoot`), all readable over LDAP. Then pick that domain's domain controller via SRV.
- go-ldap never follows referrals (§1), and AD returns them for out-of-domain DNs. Hold one lazily opened connection per domain plus one GC connection, and route by DN. Do not chase referrals: that keeps auth and TLS policy identical for every hop. This answers the map's "Cross-domain writes" question at the protocol level.

## 5. Paging, ranged retrieval, SD flags

- **Paging:** `MaxPageSize` defaults to **1000**: "To perform a search where the result might exceed this number of objects, the client MUST specify the paged search control." `MaxQueryDuration` is 120 s and `MaxConnIdleTime` is 900 s. ([MS-ADTS LDAP Policies](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3f0137a1-63df-400c-bf97-e1040f055a99)) `SearchWithPaging` handles it. For our opaque-cursor paging contract, carry the paging cookie ourselves with `ControlPaging` on a held connection. Server cookies are per-connection, which is a design constraint for the cursor ticket.
- **Ranged retrieval:** `MaxValRange` defaults to **1500** values per multi-valued attribute per search ([LDAP Policies](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3f0137a1-63df-400c-bf97-e1040f055a99)). Request `member;range=0-*`. The server returns e.g. `member;range=0-1499`. Loop with `member;range=1500-*` until the returned name ends in `-*`. ([Attribute Range Retrieval](https://learn.microsoft.com/en-us/windows/win32/adsi/attribute-range-retrieval)) go-ldap has no helper, so this is about 20 lines. For "is X a member (transitively)", prefer the matching-rule filter or `memberOf` on the user over expanding `member`.
- **SD flags** (`1.2.840.113556.1.4.801`): the value is BER `SEQUENCE { Flags INTEGER }` with OWNER 0x1, GROUP 0x2, DACL 0x4, SACL 0x8. "Specifying Flags with no bits set, or not using the … control, is equivalent to" all four. It also scopes Modify requests. ([MS-ADTS SD flags](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3888c2b7-35b9-45b7-afeb-b772aa932dd0)) Send `0x7` when reading `nTSecurityDescriptor` (a non-admin account can't read the SACL), and when writing ACLs so the SACL isn't touched. Parsing the SD itself (MS-DTYP SECURITY_DESCRIPTOR/ACL/ACE) is our code.

## 6. Decoding AD binary values

| Value | Wire format | Source |
| --- | --- | --- |
| `objectSid`, `tokenGroups` | Revision (1, must be 1), SubAuthorityCount (≤15), IdentifierAuthority (6 bytes, big-endian), then SubAuthority × uint32. AD stores the SubAuthorities little-endian. Render as `S-1-<auth>-<sub>…`. | [MS-DTYP 2.4.2.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861) |
| `objectGUID` | 16 bytes: Data1 (4), Data2 (2), Data3 (2) little-endian, then Data4 (8) as bytes. The string form byte-swaps the first three groups. For filters, escape the raw bytes (`\xx`) rather than using the string. | [MS-DTYP 2.3.4.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/001eec5a-7f8b-4293-9e21-ca349392db40) |
| `pwdLastSet`, `lastLogonTimestamp`, `lockoutTime`, `accountExpires`, `badPasswordTime` (Integer8 as a decimal string) | FILETIME: 100-ns intervals since 1601-01-01 UTC. Unix = v/10⁷ − 11644473600. Treat 0 and 0x7FFFFFFFFFFFFFFF as "never/unset". | [MS-DTYP FILETIME](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/2c57429b-fdd4-488f-b5fc-9e4cf020fcdf) |
| `whenCreated`, `whenChanged` | GeneralizedTime `YYYYMMDDHHMMSS.0Z`. Parse with `time.Parse("20060102150405.0Z07", …)`. | RFC 4517 §3.3.13 |
| Replication XML (`msDS-Repl*`) | FILETIME is already rendered as XML dateTime UTC and GUIDs as strings. | [MS-ADTS 3.1.1.3.2.28](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b4a0b2bf-95f9-40b4-9301-834ccadea40c) |

All of this is stdlib (`encoding/binary`, `time`, `fmt`). No dependency is needed.

## 7. v1 jobs: LDAP alone vs SMB/RPC/ADWS

| Job | Over LDAP? | How / what's missing |
| --- | --- | --- |
| **Sites, subnets, site links, domain controllers, FSMO** | Yes | `CN=Sites,CN=Configuration,…` (site, subnet, siteLink, server, nTDSDSA objects), `fSMORoleOwner` on the domain/RID/Infrastructure/Schema/Partitions objects, and `crossRef`s. The GC role is shown by `options` on nTDSDSA. |
| **Replication health** | Mostly | Per domain controller, read the rootDSE constructed attributes `msDS-ReplAllInboundNeighbors`, `msDS-ReplConnectionFailures`, `msDS-ReplLinkFailures`, `msDS-ReplPendingOps`. They return "exactly the same information" as DRSR `IDL_DRSGetReplInfo`, as XML (or `;binary`) ([MS-ADTS 3.1.1.3.2.28](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b4a0b2bf-95f9-40b4-9301-834ccadea40c)). This means one connection per domain controller. What's missing: forcing a sync (`repadmin /syncall`), which needs DRSR RPC. That is a write anyway and is out of v1. |
| **Lockout source** | Partly | Over LDAP: `lockoutTime`, `msDS-User-Account-Control-Computed`, and per-domain-controller `badPwdCount`/`badPasswordTime`, which are not replicated, so query each domain controller. `msDS-ReplAttributeMetaData` on the user names the domain controller that *originated* the `lockoutTime` write (`pszLastOriginatingDsaDN`) ([DS_REPL_ATTR_META_DATA](https://learn.microsoft.com/en-us/windows/win32/api/ntdsapi/ns-ntdsapi-ds_repl_attr_meta_data), [Bad passwords and lockout](https://learn.microsoft.com/en-us/archive/technet-wiki/32490.active-directory-bad-passwords-and-account-lockout)). Not over LDAP: the *caller computer* lives only in Security event 4740 on the PDC/locking domain controller, which needs the EventLog RPC (MS-EVEN6) or WinRM. That is out of reach without SMB/RPC. |
| **GPO objects and links** | Yes | `groupPolicyContainer` objects under `CN=Policies,CN=System,<domain>` (`displayName`, `versionNumber`, `flags`, `gPCFileSysPath`), plus `gPLink`/`gPOptions` on domain, OU, and site objects. |
| **GPO settings** | **No** | The template lives in SYSVOL at the `gPCFileSysPath` UNC path, reachable over DFS/SMB only ([MS-ADA1 gPCFileSysPath](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada1/6eb770b7-0c89-4a3e-a41e-2807d46880d8), [MS-GPOL glossary](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/2f362c13-9a2d-469b-8c4b-7b4045258995)). Reading it would need an SMB2/3 client in Go (a new dependency) and Kerberos/NTLM over SMB. |
| **FGPP** | Yes, with rights | `msDS-PasswordSettings` objects in `CN=Password Settings Container,CN=System,<domain>`, and `msDS-ResultantPSO` on the user. By default only Domain Admins can read PSOs, so the service account needs Read Property delegated ([FGPP step-by-step](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc770842(v=ws.10)), [FGPP in ADAC](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/fine-grained-password-policies)). The domain default policy is on the domain head (`minPwdLength`, `lockoutThreshold`, etc.). |
| ADWS (9389) | n/a | Adds nothing LDAP lacks for these jobs, and from Go it means a SOAP/.NET-framing client. Not worth it. |

## What the host needs (checklist)

- Network reach to domain controllers on 636 (and 3269 for the GC); 53 for SRV; 88 if Kerberos.
- The AD CA certificate bundle (file) to verify the domain controller certificates.
- A least-privilege service account. Its credential arrives as a file (password, or keytab plus `krb5.conf` for Kerberos). Rights are delegated per **capability**, plus Read Property on PSOs if FGPP is wanted.
- Optional config: a static domain controller list, a forced site, StartTLS instead of LDAPS.

## Open questions surfaced

- Auth decision: ship simple-bind-over-TLS only in v1, or also keytab Kerberos (it breaks under CBT Always until gokrb5 gains channel binding)?
- Paging cursor: AD paged-search cookies are bound to a connection, so how does the opaque cursor survive reconnects or multiple domain controllers (pin a connection per cursor, or re-run the search with an offset)?
- Lockout source: is "originating domain controller + per-DC badPwdCount" enough for v1, or does it need the 4740 caller machine (event-log RPC/WinRM, a new transport)?
- GPO settings: confirm v1 stays at GPO objects and links (LDAP), deferring SYSVOL/SMB.
