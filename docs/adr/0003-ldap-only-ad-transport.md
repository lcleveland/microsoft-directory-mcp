# LDAP is the only Active Directory transport

The AD side reaches the forest over LDAP alone (LDAPS 636/3269, or StartTLS on 389/3268) plus DNS. It uses no SMB, RPC, WinRM or ADWS. As a result, two things a reader might expect are missing.

**GPO settings are not read.** Reading them would need an SMB2/3 client with signing, NTLM over SMB, port 445 open to the DCs, parsers for Registry.pol, GptTmpl.inf and the GPP XML, and ADMX mapping. The only Go SMB options are the stale `hirochachacha/go-smb2` and its forks. v1 reports GPO objects and links, and returns `gPCFileSysPath` so a human can open the settings in GPMC.

**The machine that caused a lockout (event 4740) is not read.** WinRM needs Event Log Readers plus Remote Management Users on the DCs, which comes close to a remote shell on a tier-0 host. EventLog RPC (MS-EVEN6) has no mature Go library. v1 reports the LDAP facts instead: `lockoutTime`, the originating DC from `msDS-ReplAttributeMetaData`, and per-DC `badPwdCount`.

Both keep the service account least-privilege and the host's firewall needs to one protocol. Adding a second transport later is additive, but it would widen what the service account can do. Decided in [Decide on non-LDAP AD transports for v1](https://github.com/lcleveland/microsoft-directory-mcp/issues/17).
