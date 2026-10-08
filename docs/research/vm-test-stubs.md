# Research: stubbing AD and Graph for the NixOS VM test

Ticket: #7 (part of #1). The question: how do we test both **sides** hermetically in a NixOS VM
test, the way the siblings' stub tests do? Can nixpkgs Samba provision an AD DC inside a VM
test (LDAPS, a seeded user, group and OU, a password reset, a Kerberos keytab export)? How
long does that take, and how does Samba behave differently from a Windows DC? On the Graph
side, what is the smallest useful stub, and how do the siblings structure theirs?

## Answer (short)

- **AD side: run a real Samba AD DC in the VM. It's fast.** We ran an experiment on
  nixpkgs with Samba 4.23.10 (`samba4Full`), KVM, a warm store, and one VM node with 2 GiB:
  - VM boot: 7.5 s.
  - `samba-tool domain provision`: **5.5 to 6.1 s**.
  - LDAPS on 636 is open 16 s after the script starts.
  - The full probe script runs in 19 s, and the whole `nix build` takes **about 28 s** wall time.

  Everything asked for worked: LDAPS with Samba's auto-generated CA, seeding an OU, group,
  user and membership, an admin password reset via `unicodePwd` over LDAPS, a keytab export,
  `kinit -kt`, and a GSSAPI (sealed) LDAP search. That is far cheaper than netbox-mcp's real
  service test, which takes about 7 minutes.
- **It's not a module option.** `services.samba` only has `smbd`, `nmbd` and `winbindd` units.
  The default `samba` package is built `--without-ad-dc`, and nixpkgs has no AD DC test. The
  test needs about 15 lines of its own: a `samba4Full` unit whose `preStart` provisions once,
  then `samba --foreground --no-process-group`. `samba4Full` comes from cache.nixos.org (about
  150 MiB download on first fetch).
- **Graph side: a Python stdlib stub, a straight copy of falcon-mcp's `tests/vm.nix` pattern.**
  It uses `writePython3Bin` and `ThreadingHTTPServer` on `127.0.0.1`, plain HTTP, and one
  `handle_any` dispatcher that records secrets and bearers to `/tmp/stub-*`. It needs 5
  behaviours:
  - the v2.0 client-credentials token endpoint;
  - one read route that returns an `@odata.nextLink` page;
  - one route that returns a single `429` with `Retry-After: 1`;
  - one `403` that the startup probe should turn into a hidden action;
  - one write route that records its body.

  It's about 90 lines.
- **Layout: one VM node with three units** (`samba-dc`, `stub-graph`, `microsoft-directory-mcp`)
  plus the siblings' MCP session script. A second `nodes.*` entry isn't needed. `tests/eval.nix`
  copies falcon's (`lib.nixosSystem` + assertions/grep on the generated unit).

## How the siblings do it (primary source: their `tests/`)

- **ninjaone-mcp** `tests/vm.nix` (246 lines) and `docs/research/vm-test-stub.md`. Its pattern:
  - The stub is a `pkgs.writers.writePython3Bin` stdlib `http.server`, run as
    `systemd.services.stub-*` with `wantedBy = multi-user.target` and
    `before = <mcp>.service`.
  - Secrets are root-only `0400` files seeded with `systemd.tmpfiles.settings`, the same shape
    sops-nix and agenix produce.
  - The module has a `baseUrl` option pointing at `http://127.0.0.1:<port>`, with no test CA.
  - A Python MCP session probe (`initialize`, `tools/list`, `tools/call`) accepts JSON or SSE.
- **falcon-mcp** `tests/vm.nix` (338 lines) goes further. It's the template to copy:
  - The stub uses `ThreadingHTTPServer` with
    `do_GET = do_POST = do_PATCH = do_PUT = do_DELETE = handle_any`.
  - It throttles the first real search with a `429` and records it to `/tmp/stub-throttled`.
  - It returns `403` on a whole route prefix so the **startup probe** hides that action. The
    test asserts the action is missing from `tools/list` and that `falcon_status` reports the
    probe state.
  - It records the write's comment so the test can grep the **reason** in both the stub log and
    the journal (`msg="falcon write" reason=...`).
  - It sets `DEBUG=1` to prove that secrets and bearers never reach the journal.
  - The hardening subtests are shared with ninjaone: `/run/credentials` modes, `runuser -u
    nobody` fails, no secret in `/proc/<pid>/{cmdline,environ}`, `systemd-analyze security`
    under 3.0, `nsenter ... test -w /etc` fails, and the restart comes back healthy.
  - falcon-mcp has **no** `docs/research/vm-test-stub.md`. Its `tests/vm.nix` header comment is
    the only write-up.
- **eval.nix (both siblings):** `lib.nixosSystem` with the module, a dummy `package`
  (`writeShellScriptBin ... "exit 0"`), and a tmpfs root. A `failed` helper collects
  assertion messages, and `unitCheck` greps the rendered unit. There's no VM, so it's fast.
  Copy it as is and add cases for "AD only", "Entra only", "neither side configured" and
  "LDAP URL not ldaps without opt-in".

## AD side: Samba AD DC in a VM test

### What nixpkgs provides (primary source: nixpkgs master)

- `nixos/modules/services/network-filesystems/samba.nix` defines `samba-smbd`, `samba-nmbd`
  and `samba-winbindd` units only. It has no `samba` (AD DC) unit and no provisioning.
- `pkgs/servers/samba/4.x.nix` sets `enableDomainController ? false`, which adds
  `--without-ad-dc`. It's version 4.23.10 at the time of writing.
- `pkgs/top-level/all-packages.nix` defines `samba4Full = samba4.override { enableLDAP = true;
  enablePrinting = true; enableMDNS = true; enableDomainController = true; ... }`.
- `nixos/tests/samba.nix` covers only a guest CIFS share. A GitHub code search of nixpkgs
  for `samba-tool domain provision` finds no tests.
- The NixOS wiki Samba page uses the same approach as below: an overlay with
  `enableDomainController`, a hand-written unit running `samba --foreground --no-process-group`,
  and `samba-tool domain provision`.

### The working node (verified in this experiment)

```nix
nodes.machine = { ... }: {
  virtualisation.memorySize = 2048;          # untested lower
  networking.hostName = "dc1";
  networking.domain = "corp.example.com";    # gives /etc/hosts dc1.corp.example.com, matches the TLS cert CN
  security.krb5.enable = true;               # without it /etc/krb5.conf is not written: "Cannot find KDC"
  security.krb5.settings = {
    libdefaults.default_realm = "CORP.EXAMPLE.COM";
    realms."CORP.EXAMPLE.COM".kdc = [ "dc1.corp.example.com" ];
  };
  systemd.services.samba-dc = {
    wantedBy = [ "multi-user.target" ];
    before = [ "microsoft-directory-mcp.service" ];
    path = [ pkgs.samba4Full ];
    preStart = ''
      if [ ! -e /var/lib/samba-dc/private/sam.ldb ]; then
        samba-tool domain provision --server-role=dc --use-rfc2307 \
          --dns-backend=SAMBA_INTERNAL --realm=CORP.EXAMPLE.COM --domain=CORP \
          --adminpass=<placeholder> --targetdir=/var/lib/samba-dc --host-ip=127.0.0.1
        sed -i '/\[global\]/a old password allowed period = 0' /var/lib/samba-dc/etc/smb.conf
      fi
    '';
    serviceConfig = {
      ExecStart = "${pkgs.samba4Full}/sbin/samba --foreground --no-process-group -s /var/lib/samba-dc/etc/smb.conf";
      # "samba" too: the compiled-in ntp_signd path is /var/lib/samba/ntp_signd; without it samba exits.
      StateDirectory = [ "samba-dc" "samba" ];
    };
  };
};
```

Pitfalls we hit along the way:

- **The `/var/lib/samba` path.** `--targetdir` keeps state in its own directory, but samba
  still `mkdir`s the compiled-in `/var/lib/samba/ntp_signd` and exits if it can't.
  `wait_for_unit` still passes in that case, because `Type=simple`, so wait on
  `wait_for_open_port(636)` instead.
- **Option persistence.** `samba-tool domain provision --option=...` did **not** persist
  `old password allowed period` into the generated smb.conf (`testparm` still said 60). That's
  why the snippet appends it with `sed`.
- **Missing `/etc/krb5.conf`.** NixOS only writes it when `security.krb5.enable = true`.

### Results per requirement (each a `subtest` in the probe)

| Requirement | How | Result |
|---|---|---|
| Provision time | `date` around `samba-tool domain provision` | 5.5 to 6.1 s (3 runs) |
| LDAPS | Samba auto-generates `private/tls/{ca,cert,key}.pem` on first start; `LDAPTLS_CACERT=.../ca.pem ldapsearch -H ldaps://dc1.corp.example.com` | works; cert CN is the FQDN |
| Seed OU/group/user | `samba-tool ou add`, `group add --groupou`, `user create --userou`, `group addmembers` | 1.6 s total |
| Read attrs | `memberOf`, `userAccountControl: 512`, `msDS-UserPasswordExpiryTimeComputed` | returned (constructed attr works) |
| Paged results | `ldapsearch -E pr=2/noprompt` | works |
| Password reset | `ldapmodify` replace `unicodePwd::` (base64 of UTF-16LE `"pw"`) over LDAPS as Administrator | works; new password binds |
| Keytab export | `samba-tool domain exportkeytab /tmp/svc.keytab --principal=svc-mcp@CORP.EXAMPLE.COM` | 3 enctypes, kvno 2 |
| Kerberos | `kinit -kt` then `ldapsearch -H ldap://... -Y GSSAPI` | works (SASL sign/seal over plain 389) |

The probe is not committed. It lived in a scratch flake outside the repo. The snippet above
and this table hold everything needed to rebuild it.

### Samba DC vs Windows DC: what changes what the test can prove

Observed in the VM:

- **`ldap server require strong auth = yes` is the default.** A simple bind over plain `ldap://`
  fails with `Strong(er) authentication required (8) ... Transport encryption required`. The
  smb.conf docs say `yes` allows simple binds only over TLS, and SASL over TLS only **with
  TLS channel bindings**. Plain connections allow only SASL with sign or seal. That maps to
  Windows `LdapEnforceChannelBinding=2`. A Windows DC's behaviour depends on its LDAP
  signing and channel-binding policy, so Samba's default is the strict end of it. That's
  good for us: if the server works against Samba, it works against a hardened DC.
- **The old password keeps working for 60 minutes after a reset, over simple bind.**
  `old password allowed period` defaults to 60 (smb.conf: "permit an NTLM login after a
  password change or reset using the old password"). Samba applies it to LDAP simple binds
  too: the old password still bound until we set it to `0`, after which it got `49 ... data 52e`.
  `kinit` with the old password was refused either way. Any test that asserts "the old
  password no longer works" needs either the `sed` line or Kerberos.
- **Admin reset ignores password history.** `samba-tool user setpassword` back to the previous
  password succeeded. That matches Windows, where reset (as opposed to change) skips history.
- **Subtree search references.** A subtree search from the domain root returns `ref:`
  continuations for `CN=Configuration`, `DomainDnsZones` and `ForestDnsZones`. Windows does the
  same, so the LDAP client must ignore or handle referrals rather than fail. It's worth an
  explicit assertion in the test.
- The default domain password policy has a max age of 42 days (shown by `kinit`).

From Samba docs (wiki FAQ, "Raising the Functional Levels"); none of these were exercised:

- Functional levels 2012_R2 need Samba 4.19+ and 2016 needs 4.20+ (`samba-tool domain level
  raise`). 4.23 covers both.
- No DFS-R, so SYSVOL isn't replicated. Trusts are experimental (no SID filtering). There's no
  ADWS/PowerShell endpoint, which doesn't matter for an LDAP client.
- A single VM is **one domain, one DC**. Multi-domain forest routing, referrals across
  domains, GC on 3268/3269 across domains and replication lag can't be shown without more
  nodes. See the open questions.

### What the MCP module needs for the AD half of the test

- **An LDAP URL option** (e.g. `ldaps://dc1.corp.example.com`) plus a **CA file option**.
  Samba writes `ca.pem` under `private/tls/`. The test should copy it to a world-readable path
  (or hand it over via `LoadCredential`) before the MCP unit starts, so the hardened
  DynamicUser can read it. Don't set `LDAPTLS_REQCERT=never`: the test should prove the CA
  option works.
- **The bind credential as a file.** Either a password file (simple bind over LDAPS) or a keytab
  (`samba-tool domain exportkeytab`, GSSAPI). Both are cheap to seed from the test script
  after the DC is up, then `systemctl restart microsoft-directory-mcp` (or order the MCP
  unit `after` a oneshot that seeds). Which one(s) v1 supports is the auth decision, not
  this ticket.
- **Assertions to add** beyond the sibling set:
  - a write (e.g. reset alice's password, `reason` set) followed by the new password binding
    and the old one failing, with the `sed` line in place;
  - the reason appears in the journal;
  - the bind password never appears in the journal or `/proc`;
  - search references don't break a domain-root search.

## Graph side: the smallest stub

What it has to emulate (primary source: Microsoft Learn):

- **Token:** `POST /{tenant}/oauth2/v2.0/token`, form-encoded `client_id`,
  `scope=https://graph.microsoft.com/.default`, `grant_type=client_credentials`, and either
  `client_secret` (Basic auth also allowed) or `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
  plus `client_assertion` (certificate). Success returns
  `{"token_type":"Bearer","expires_in":3599,"access_token":"..."}`. An error is a `400` with
  `error`, `error_description`, `error_codes`, `trace_id`, `correlation_id`.
  - The stub records the secret, or the assertion JWT, so the test can grep it.
  - If certificate auth is chosen, the stub can't verify the signature cheaply. It should
    decode the JWT header and payload and record `aud`/`iss`/`sub` and the `x5t#S256`
    header, which is enough to prove the cert was loaded and used.
- **Paging:** `@odata.nextLink` is a full URL to use as-is. It carries `$skiptoken`/`$skip`
  and every original query parameter, and the last page omits it. A page can be empty.
  `ConsistencyLevel` isn't forwarded to later pages automatically, and `@odata.count` appears
  only on page 1.
  - The stub returns page 1 for `GET /v1.0/users?$top=...` with
    `"@odata.nextLink": "http://127.0.0.1:<port>/v1.0/users?$top=...&$skiptoken=stub2"`,
    then page 2 with none.
  - If the server pages with `$count=true`, assert that `ConsistencyLevel: eventual` was sent
    on page 2 as well.
- **Throttling:** `429` with header `Retry-After: <seconds>` and body
  `{"error":{"code":"TooManyRequests","message":...,"innerError":{...}}}`. Back off for
  `Retry-After`, and use exponential backoff if it's absent.
  - The stub throttles the first non-probe call once with `Retry-After: 1` and records it
    (falcon's `throttled` flag).
- **Permission refusal:** a `403` with the Graph error envelope
  (`{"error":{"code":"Authorization_RequestDenied",...}}`) on one probe route, so the test can
  assert the startup probe hides that action. That only applies if #1's "Startup probe"
  question lands falcon-style.
- **One write:** e.g. `PATCH /v1.0/users/{id}` (`accountEnabled:false`) records its body.
  Graph has no reason field, so the reason is asserted in the journal only.
- **Status probe:** `GET /v1.0/organization` returns one placeholder org (made-up GUID,
  `example.com` verified domain).

Module options this implies: an **authority/login base URL override** and a **Graph base
URL override** (or one `baseUrl` that derives both, like ninjaone, with paths
`/{tenant}/oauth2/v2.0/token` and `/v1.0/...`), restricted to loopback when not `https`. That's
the same hardening question ninjaone raised. Pointing a real `login.microsoftonline.com` name
at the stub with a test CA was rejected by ninjaone for the same reason as here: it only tests
Go's TLS plumbing.

## Recommended test shape

- `tests/vm.nix`: one node, about 400 to 450 lines, compared with falcon's 338.
  - `samba-dc` unit (above) and `stub-graph` unit (falcon-style `handle_any`).
  - A oneshot or test-script step seeds the OU, group, user and the MCP bind credential, and
    copies `ca.pem`.
  - tmpfiles-seeded `0400` secrets for the Graph client secret and the HTTP bearer.
  - The MCP session script covers `ad_status`/`entra_status`, one AD search, one AD write,
    one Entra paged list, and one Entra write.
  - The sibling hardening and journal-leak subtests are kept.
- **Expected runtime:** under a minute on KVM with a warm store. Samba adds about 6 s of
  provisioning and the Python stub adds nothing measurable.
- `tests/eval.nix`: falcon's file adapted, with the side-optional cases listed above.

## Sources

- nixpkgs master:
  - `nixos/modules/services/network-filesystems/samba.nix`
  - `pkgs/servers/samba/4.x.nix` (`enableDomainController`, `--without-ad-dc`, version 4.23.10)
  - `pkgs/top-level/all-packages.nix` (`samba4Full`)
  - `nixos/tests/samba.nix`
  - https://github.com/NixOS/nixpkgs
- NixOS wiki, Samba (AD DC section): https://wiki.nixos.org/wiki/Samba
- NixOS manual, Writing Tests: https://nixos.org/manual/nixos/stable/#sec-writing-nixos-tests
- Samba wiki:
  - Configuring LDAPS on a Samba AD DC: https://wiki.samba.org/index.php/Configuring_LDAP_over_SSL_(LDAPS)_on_a_Samba_AD_DC
  - Port usage: https://wiki.samba.org/index.php/Samba_AD_DC_Port_Usage
  - FAQ: https://wiki.samba.org/index.php/FAQ
  - Raising the Functional Levels: https://wiki.samba.org/index.php/Raising_the_Functional_Levels
- Samba source, smb.conf parameter docs:
  - `docs-xml/smbdotconf/ldap/ldapserverrequirestrongauth.xml`
  - `docs-xml/smbdotconf/security/oldpasswordallowedperiod.xml`
  - https://gitlab.com/samba-team/samba
- Microsoft Learn:
  - Client credentials flow: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow
  - Paging: https://learn.microsoft.com/en-us/graph/paging
  - Throttling: https://learn.microsoft.com/en-us/graph/throttling
- Sibling repos:
  - https://github.com/lcleveland/ninjaone-mcp (`tests/vm.nix`, `tests/eval.nix`, `docs/research/vm-test-stub.md`)
  - https://github.com/lcleveland/falcon-mcp (`tests/vm.nix`, `tests/eval.nix`)
- The experiment: a local `pkgs.testers.runNixOSTest` probe against nixpkgs with Samba
  4.23.10, run 5 times. The timings above come from its `PROVISION_SECONDS`/`UP_SECONDS`/
  `TOTAL_SCRIPT_SECONDS` prints.
