# VM test: the real binary against a real Samba AD DC and a stub Graph, on
# one node with three units (docs/research/vm-test-stubs.md):
#
#   samba-dc                 Samba AD DC, provisioned in preStart; LDAPS with
#                            a CA and certificate made there by openssl
#   stub-graph               stdlib Python Graph: v2.0 token endpoint that
#                            verifies the client assertion and issues a JWT
#                            with a roles claim; /organization, and the probe's
#                            subscribedSkus (no P1), managedDevices and signIns (403);
#                            /users in two nextLink pages, the second 429 once;
#                            a user by id or UPN, a group's members, /devices,
#                            /beta/organization, apps and SPs with credentials, and
#                            directory audit events (activityDisplayName filters);
#                            a synced user whose SID is vmuser042's, read from
#                            /var/lib/samba-dc/vm-synced-sid (onPremisesSyncBehavior refused: 403)
#                            PATCH of a user's accountEnabled or passwordProfile, empty role assignments,
#                            memberships and ownerships; every write recorded in /tmp/stub-writes
#   microsoft-directory-mcp  the module's HTTP service
#
# One full MCP session calls ad_status (a simple bind over LDAPS, trusting
# Samba's CA via --ad-ca-file) and entra_status (a token the stub verified).
# Later issues add stub routes and seed data, and the hardening subtests.
{ pkgs, self }:

let
  inherit (pkgs) lib;
  stubPort = 9444;
  mcpPort = 8235;

  realm = "CORP.EXAMPLE.COM";
  dcHost = "dc1.corp.example.com";
  adminPass = "VmTest-Admin-Pass-1!";
  bindUser = "svc-mcp";
  bindPass = "VmTest-Bind-Pass-1!";
  lockedPass = "VmTest-Locked-Pass-1!";
  resetPass = "VmTest-Reset-Pass-1!";
  tenant = "00000000-0000-0000-0000-0000000000aa";
  clientId = "00000000-0000-0000-0000-0000000000bb";
  httpToken = "mcp-http-bearer";
  smbConf = "/var/lib/samba-dc/etc/smb.conf";
  tlsDir = "/var/lib/samba-dc/vm-tls";
  openssl = lib.getExe pkgs.openssl;
  # The certificate half of the Entra fixture, readable by the stub.
  certPublic = "/run/entra-cert-public.pem";
  # vmuser042's objectSid, written at provisioning for the stub's synced user.
  syncedSid = "/var/lib/samba-dc/vm-synced-sid";
  # An unsigned JWT the server decodes for the startup probe. Payload:
  # {"aud":"https://graph.microsoft.com","roles":["Organization.Read.All","User.Read.All","LicenseAssignment.Read.All","GroupMember.Read.All","Device.Read.All","Application.Read.All","AuditLog.Read.All","User.EnableDisableAccount.All","User.RevokeSessions.All","RoleManagement.Read.Directory","User-PasswordProfile.ReadWrite.All","UserAuthMethod-TAP.ReadWrite.All","UserAuthenticationMethod.ReadWrite.All","GroupMember.ReadWrite.All"]}
  accessToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20iLCJyb2xlcyI6WyJPcmdhbml6YXRpb24uUmVhZC5BbGwiLCJVc2VyLlJlYWQuQWxsIiwiTGljZW5zZUFzc2lnbm1lbnQuUmVhZC5BbGwiLCJHcm91cE1lbWJlci5SZWFkLkFsbCIsIkRldmljZS5SZWFkLkFsbCIsIkFwcGxpY2F0aW9uLlJlYWQuQWxsIiwiQXVkaXRMb2cuUmVhZC5BbGwiLCJVc2VyLkVuYWJsZURpc2FibGVBY2NvdW50LkFsbCIsIlVzZXIuUmV2b2tlU2Vzc2lvbnMuQWxsIiwiUm9sZU1hbmFnZW1lbnQuUmVhZC5EaXJlY3RvcnkiLCJVc2VyLVBhc3N3b3JkUHJvZmlsZS5SZWFkV3JpdGUuQWxsIiwiVXNlckF1dGhNZXRob2QtVEFQLlJlYWRXcml0ZS5BbGwiLCJVc2VyQXV0aGVudGljYXRpb25NZXRob2QuUmVhZFdyaXRlLkFsbCIsIkdyb3VwTWVtYmVyLlJlYWRXcml0ZS5BbGwiXX0.stub";

  # Seed data, ldbadd-ed into sam.ldb at provisioning: 250 users (more than
  # one page), vm-team with five users and the nested vm-sub (two more);
  # GPOs a and b linked to OU=vm-ou (b enforced, link order 1), and
  # OU=vm-child under it blocking inheritance. The PSO vm-pso, applied to
  # vm-team, and the user vm-locked are created with samba-tool after.
  base = "DC=corp,DC=example,DC=com";
  userDN = n: "CN=vmuser${lib.fixedWidthNumber 3 n},CN=Users,${base}";
  gpoA = "{A1A1A1A1-0000-4000-8000-000000000001}";
  gpoB = "{B2B2B2B2-0000-4000-8000-000000000002}";
  gpoDN = guid: "CN=${guid},CN=Policies,CN=System,${base}";
  gpo = guid: name: flags: ''
    dn: ${gpoDN guid}
    objectClass: groupPolicyContainer
    displayName: ${name}
    flags: ${toString flags}
    versionNumber: 0
    gPCFileSysPath: \\corp.example.com\sysvol\corp.example.com\Policies\${guid}

  '';
  seedLdif = pkgs.writeText "seed.ldif" (
    lib.concatMapStrings (n: ''
      dn: ${userDN n}
      objectClass: user
      sAMAccountName: vmuser${lib.fixedWidthNumber 3 n}
      userPrincipalName: vmuser${lib.fixedWidthNumber 3 n}@corp.example.com

    '') (lib.range 1 250)
    + ''
      dn: CN=vm-sub,CN=Users,${base}
      objectClass: group
      sAMAccountName: vm-sub
      member: ${userDN 6}
      member: ${userDN 7}

      dn: CN=vm-team,CN=Users,${base}
      objectClass: group
      sAMAccountName: vm-team
      ${
        lib.concatMapStrings (n: "member: ${userDN n}\n") (lib.range 1 5)
      }member: CN=vm-sub,CN=Users,${base}

    ''
    + gpo gpoA "vm-gpo-a" 0
    + gpo gpoB "vm-gpo-b" 1
    + ''
      dn: OU=vm-ou,${base}
      objectClass: organizationalUnit
      gPLink: [LDAP://cn=${gpoA},cn=policies,cn=system,${base};0][LDAP://cn=${gpoB},cn=policies,cn=system,${base};2]

      dn: OU=vm-child,OU=vm-ou,${base}
      objectClass: organizationalUnit
      gPOptions: 1
    ''
  );

  # Routes are (method, path) -> handler; later issues add to ROUTES and SEED.
  stub = pkgs.writers.writePython3Bin "stub-graph" { flakeIgnore = [ "E501" ]; } ''
    import base64
    import functools
    import hashlib
    import http.server
    import json
    import os
    import re
    import ssl
    import subprocess
    import tempfile
    import time
    import urllib.parse

    PORT = ${toString stubPort}
    TENANT = ${builtins.toJSON tenant}
    CLIENT_ID = ${builtins.toJSON clientId}
    CERT = ${builtins.toJSON certPublic}
    OPENSSL = "${lib.getExe pkgs.openssl}"
    TOKEN_PATH = "/" + TENANT + "/oauth2/v2.0/token"
    TOKEN_URL = "http://127.0.0.1:%d%s" % (PORT, TOKEN_PATH)
    ACCESS_TOKEN = ${builtins.toJSON accessToken}
    SYNCED_SID = ${builtins.toJSON syncedSid}

    SEED = {
        "organization": [{
            "id": TENANT,
            "displayName": "Example Org",
            "onPremisesSyncEnabled": True,
            "onPremisesLastSyncDateTime": "2026-01-01T00:00:00Z",
        }],
        # Exchange only: no P1 (AAD_PREMIUM) and no P2.
        "subscribedSkus": [{
            "skuId": "00000000-0000-0000-0000-0000000000c1",
            "skuPartNumber": "EXCHANGESTANDARD",
            "capabilityStatus": "Enabled",
            "servicePlans": [{
                "servicePlanId": "9aaf7827-d63c-4b61-89c3-182f06f82e5c",
                "servicePlanName": "EXCHANGE_S_STANDARD",
                "provisioningStatus": "Success",
            }],
        }],
        "managedDevices": [],
        "groups": [],
        # Two pages of two and one, the second answered 429 once.
        "users": [{"@odata.type": "#microsoft.graph.user",
                   "id": "00000000-0000-0000-0000-00000000010%d" % n,
                   "displayName": "Entra User %d" % n,
                   "userPrincipalName": "entra-user%d@example.com" % n,
                   "accountEnabled": True,
                   "assignedLicenses": [{"skuId": "00000000-0000-0000-0000-0000000000c1"}]} for n in (1, 2, 3)],
        "devices": [{"@odata.type": "#microsoft.graph.device",
                     "id": "00000000-0000-0000-0000-000000000201",
                     "deviceId": "00000000-0000-0000-0000-000000000301",
                     "displayName": "entra-device1", "operatingSystem": "Windows"}],
    }


    # Credentials ending 10 and 90 days after the stub starts, and an expired one.
    def days(n):
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + n * 86400))


    SEED["applications"] = [{"id": "00000000-0000-0000-0000-000000000501", "appId": "00000000-0000-0000-0000-000000000601",
                             "displayName": "vm-app", "passwordCredentials": [
                                 {"keyId": "00000000-0000-0000-0000-000000000701", "displayName": "soon", "endDateTime": days(10), "hint": "abc"},
                                 {"keyId": "00000000-0000-0000-0000-000000000702", "displayName": "late", "endDateTime": days(90), "hint": "abc"}],
                             "keyCredentials": []}]
    SEED["servicePrincipals"] = [{"id": "00000000-0000-0000-0000-000000000502", "appId": "00000000-0000-0000-0000-000000000601",
                                  "displayName": "vm-app", "passwordCredentials": [], "keyCredentials": [
                                      {"keyId": "00000000-0000-0000-0000-000000000703", "endDateTime": days(-1), "key": "MIIC"}]}]
    # Directory audit events: a user added, then password writeback enabled.
    SEED["directoryAudits"] = [
        {"id": "audit-2", "activityDateTime": "2026-01-02T00:00:00Z", "activityDisplayName": "Enable password writeback for directory",
         "category": "DirectoryManagement", "result": "success", "initiatedBy": {}, "targetResources": []},
        {"id": "audit-1", "activityDateTime": "2026-01-01T00:00:00Z", "activityDisplayName": "Add user", "category": "UserManagement",
         "result": "success", "initiatedBy": {"user": {"userPrincipalName": "admin@example.com"}},
         "targetResources": [{"id": "00000000-0000-0000-0000-000000000101", "displayName": "Entra User 1", "modifiedProperties": []}]},
    ]


    def synced():
        """The synced user, linked to vmuser042 by SID (read once Samba has provisioned)."""
        with open(SYNCED_SID) as fh:
            sid = fh.read().strip()
        return {"@odata.type": "#microsoft.graph.user", "id": "00000000-0000-0000-0000-000000000109",
                "displayName": "Synced User", "userPrincipalName": "synced-user@example.com", "accountEnabled": True,
                "onPremisesSyncEnabled": True, "onPremisesSecurityIdentifier": sid}


    # A group of user 1 and the device.
    SEED["members"] = {"00000000-0000-0000-0000-000000000401": [SEED["users"][0], SEED["devices"][0]]}
    THROTTLED = set()


    def record(name, value):
        with open("/tmp/stub-" + name, "a") as fh:
            fh.write(value + "\n")


    def b64url(s):
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


    def verify_assertion(jwt):
        """Returns None if the client assertion is good, else why not."""
        parts = jwt.split(".")
        if len(parts) != 3:
            return "not a JWS"
        header = json.loads(b64url(parts[0]))
        claims = json.loads(b64url(parts[1]))
        with open(CERT) as fh:
            der = ssl.PEM_cert_to_DER_cert(fh.read())
        x5t = base64.urlsafe_b64encode(hashlib.sha256(der).digest()).decode().rstrip("=")
        now = time.time()
        if header.get("alg") != "PS256":
            return "alg %r" % header.get("alg")
        if header.get("x5t#S256") != x5t:
            return "x5t#S256 does not match the certificate"
        if claims.get("aud") != TOKEN_URL:
            return "aud %r" % claims.get("aud")
        if claims.get("iss") != CLIENT_ID or claims.get("sub") != CLIENT_ID:
            return "iss/sub %r/%r" % (claims.get("iss"), claims.get("sub"))
        if not now - 60 < claims.get("exp", 0) <= now + 600:
            return "exp is not short: %r" % claims.get("exp")
        with tempfile.TemporaryDirectory() as d:
            pub, data, sig = (os.path.join(d, n) for n in ("pub.pem", "data", "sig"))
            subprocess.run([OPENSSL, "x509", "-in", CERT, "-pubkey", "-noout", "-out", pub], check=True)
            with open(data, "w") as fh:
                fh.write(parts[0] + "." + parts[1])
            with open(sig, "wb") as fh:
                fh.write(b64url(parts[2]))
            ok = subprocess.run([OPENSSL, "dgst", "-sha256", "-verify", pub,
                                 "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:-1",
                                 "-signature", sig, data], capture_output=True)
            if ok.returncode != 0:
                return "signature: " + ok.stdout.decode() + ok.stderr.decode()
        return None


    def token(h, query):
        form = urllib.parse.parse_qs(h.body())
        if form.get("client_assertion_type") != ["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"]:
            return h.reply(400, {"error": "invalid_request", "error_description": "no client assertion"})
        why = verify_assertion(form.get("client_assertion", [""])[0])
        if why is not None:
            record("rejected", why)
            return h.reply(401, {"error": "invalid_client", "error_description": why})
        record("verified", form.get("client_id", [""])[0])
        h.reply(200, {"token_type": "Bearer", "expires_in": 3599, "access_token": ACCESS_TOKEN})


    def organization(h, query):
        h.reply(200, {"value": SEED["organization"]})


    def listing(name):
        return lambda h, query: h.reply(200, {"value": SEED[name]})


    def sid_filter(query):
        """The SID of an onPremisesSecurityIdentifier eq filter, or None."""
        m = re.fullmatch(r"onPremisesSecurityIdentifier eq '([^']*)'", query.get("$filter", [""])[0])
        return m and m.group(1)


    def by_sid(name):
        """Lists name, or only its objects with the filter's SID."""
        def handler(h, query):
            objs = SEED[name] + ([synced()] if name == "users" else [])
            sid = sid_filter(query)
            h.reply(200, {"value": [o for o in objs if sid is None or o.get("onPremisesSecurityIdentifier") == sid]})
        return handler


    def users(h, query):
        if sid_filter(query):
            return by_sid("users")(h, query)
        if query.get("$skiptoken") != ["p2"]:
            return h.reply(200, {"value": SEED["users"][:2],
                                 "@odata.nextLink": "http://127.0.0.1:%d/v1.0/users?$skiptoken=p2" % PORT})
        if "users-p2" not in THROTTLED:
            THROTTLED.add("users-p2")
            record("throttled", h.path)
            return h.reply(429, {"error": {"code": "TooManyRequests", "message": "throttled"}}, {"Retry-After": "1"})
        h.reply(200, {"value": SEED["users"][2:]})


    def user(h, query, key):
        for u in SEED["users"] + [synced()]:
            if urllib.parse.unquote(key) in (u["id"], u["userPrincipalName"]):
                return h.reply(200, u)
        h.error(404, "Request_ResourceNotFound", key)


    def group_members(h, query, key):
        if key not in SEED["members"]:
            return h.error(404, "Request_ResourceNotFound", key)
        h.reply(200, {"value": SEED["members"][key]})


    def audits(h, query):
        """Honours only activityDisplayName eq filters: an event is kept if its name is quoted in $filter."""
        f = query.get("$filter", [""])[0]
        h.reply(200, {"value": [e for e in SEED["directoryAudits"] if not f or "'" + e["activityDisplayName"] + "'" in f]})


    def user_patch(h, query, key):
        """Sets accountEnabled on a seeded user, or takes a passwordProfile; the synced user is never written."""
        body = json.loads(h.body())
        for u in SEED["users"]:
            if urllib.parse.unquote(key) in (u["id"], u["userPrincipalName"]):
                u.update({k: v for k, v in body.items() if k == "accountEnabled"})
                h.send_response(204)
                return h.end_headers()
        h.error(404, "Request_ResourceNotFound", key)


    def none(h, query, key):
        h.reply(200, {"value": []})


    def no_grant(h, query, key):
        h.error(403, "Authorization_RequestDenied", "Insufficient privileges to complete the operation.")


    def no_premium(h, query):
        h.error(403, "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
                "Neither tenant is B2C or tenant doesn't have premium license")


    ROUTES = {
        ("POST", TOKEN_PATH): token,
        ("GET", "/v1.0/organization"): organization,
        ("GET", "/v1.0/subscribedSkus"): listing("subscribedSkus"),
        ("GET", "/v1.0/deviceManagement/managedDevices"): listing("managedDevices"),
        ("GET", "/v1.0/auditLogs/signIns"): no_premium,
        ("GET", "/v1.0/auditLogs/directoryAudits"): audits,
        ("GET", "/v1.0/users"): users,
        ("GET", "/v1.0/devices"): by_sid("devices"),
        ("GET", "/v1.0/groups"): by_sid("groups"),
        ("GET", "/v1.0/applications"): listing("applications"),
        ("GET", "/v1.0/servicePrincipals"): listing("servicePrincipals"),
        ("GET", "/beta/organization"): organization,
        # No role holders: nothing is protected.
        ("GET", "/v1.0/roleManagement/directory/roleAssignments"): lambda h, query: none(h, query, None),
    }
    # (method, path pattern) -> handler(h, query, the pattern's group).
    PATTERNS = [
        ("GET", re.compile(r"/v1\.0/users/([^/]+)"), user),
        ("PATCH", re.compile(r"/v1\.0/users/([^/]+)"), user_patch),
        ("GET", re.compile(r"/v1\.0/users/([^/]+)/(?:transitiveMemberOf|ownedObjects)"), none),
        ("GET", re.compile(r"/v1\.0/groups/([^/]+)/members"), group_members),
        ("GET", re.compile(r"/v1\.0/(users|groups)/[^/]+/onPremisesSyncBehavior"), no_grant),
    ]
    UNAUTHENTICATED = {TOKEN_PATH}


    class Handler(http.server.BaseHTTPRequestHandler):
        def reply(self, status, payload, headers={}):
            body = json.dumps(payload).encode()
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def error(self, status, code, message):
            self.reply(status, {"error": {"code": code, "message": message}})

        def body(self):
            n = int(self.headers.get("Content-Length", "0"))
            return self.rfile.read(n).decode()

        def handle_any(self):
            url = urllib.parse.urlparse(self.path)
            route = ROUTES.get((self.command, url.path))
            if url.path not in UNAUTHENTICATED:
                if self.command != "GET":
                    record("writes", self.command + " " + url.path)
                bearer = self.headers.get("Authorization", "")
                record("bearers", bearer)
                if bearer != "Bearer " + ACCESS_TOKEN:
                    return self.error(401, "InvalidAuthenticationToken", "bad bearer")
            for method, pattern, handler in PATTERNS:
                m = pattern.fullmatch(url.path)
                if route is None and method == self.command and m:
                    route = functools.partial(handler, key=m.group(1))
            if route is None:
                return self.error(404, "Request_ResourceNotFound", url.path)
            route(self, urllib.parse.parse_qs(url.query))

        do_GET = do_POST = do_PATCH = do_PUT = do_DELETE = handle_any

        def log_message(self, *args):
            pass


    http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
  '';

  # A full MCP session over streamable HTTP. Streamable HTTP may answer as
  # JSON or as an SSE frame; accept both.
  session = pkgs.writers.writePython3Bin "mcp-session" { flakeIgnore = [ "E501" ]; } ''
    import json
    import urllib.request

    URL = "http://127.0.0.1:${toString mcpPort}/mcp"
    BEARER = ${builtins.toJSON httpToken}
    ids = iter(range(1, 1000))


    def post(payload, session=None):
        req = urllib.request.Request(URL, data=json.dumps(payload).encode(), method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json, text/event-stream")
        req.add_header("Authorization", "Bearer " + BEARER)
        if session:
            req.add_header("Mcp-Session-Id", session)
        resp = urllib.request.urlopen(req, timeout=30)
        raw = resp.read().decode()
        for line in raw.splitlines():
            if line.startswith("data:"):
                raw = line[5:].strip()
                break
        return resp.headers.get("Mcp-Session-Id"), json.loads(raw) if raw.strip() else {}


    session, init = post({
        "jsonrpc": "2.0", "id": next(ids), "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "vm-test", "version": "0"}},
    })
    assert init["result"]["serverInfo"]["name"] == "microsoft-directory-mcp", init
    post({"jsonrpc": "2.0", "method": "notifications/initialized"}, session)


    def call(name, args):
        _, out = post({"jsonrpc": "2.0", "id": next(ids), "method": "tools/call",
                       "params": {"name": name, "arguments": args}}, session)
        res = out["result"]
        assert not res.get("isError"), f"{name} {args}: {res}"
        return res["structuredContent"]


    def refused(name, args):
        _, out = post({"jsonrpc": "2.0", "id": next(ids), "method": "tools/call",
                       "params": {"name": name, "arguments": args}}, session)
        res = out["result"]
        assert res.get("isError"), f"{name} {args} was not refused: {res}"
        return res["content"][0]["text"]


    _, listed = post({"jsonrpc": "2.0", "id": next(ids), "method": "tools/list"}, session)
    tools = sorted(t["name"] for t in listed["result"]["tools"])
    assert tools == ["ad_api", "ad_computer", "ad_gpo", "ad_group", "ad_object", "ad_ou", "ad_policy", "ad_status", "ad_topology", "ad_user",
                     "entra_api", "entra_app", "entra_audit", "entra_device", "entra_group", "entra_license", "entra_org", "entra_role", "entra_status", "entra_user"], tools

    ad = call("ad_status", {})
    print("ad_status", json.dumps(ad))
    assert ad["bound"] and ad["tls"] == "ldaps" and "tls_warning" not in ad, ad
    assert ad["dc"] == "${dcHost}:636", ad
    assert ad["root_dse"]["default_naming_context"] == "DC=corp,DC=example,DC=com", ad
    assert "CN=Configuration,DC=corp,DC=example,DC=com" in ad["root_dse"]["naming_contexts"], ad
    # --ad-dc role detection: the one DC is the domain's PDC emulator.
    assert ad["domains"] == [{"domain": "corp.example.com", "dc": "${dcHost}:636", "pdc": "${dcHost}:636", "pdc_reachable": True}], ad

    entra = call("entra_status", {})
    print("entra_status", json.dumps(entra))
    assert entra["authenticated"] and entra["cloud"] == "global", entra
    assert entra["on_premises_sync_enabled"] is True, entra
    assert entra["on_premises_last_sync"] == "2026-01-01T00:00:00Z", entra

    # The startup probe: the roles claim decoded, P1 absent from subscribedSkus,
    # Intune present from its read probe. Later issues assert their hidden actions.
    probe = entra["probe"]
    assert probe["roles"] == ["Organization.Read.All", "User.Read.All", "LicenseAssignment.Read.All", "GroupMember.Read.All", "Device.Read.All", "Application.Read.All", "AuditLog.Read.All", "User.EnableDisableAccount.All", "User.RevokeSessions.All", "RoleManagement.Read.Directory", "User-PasswordProfile.ReadWrite.All", "UserAuthMethod-TAP.ReadWrite.All", "UserAuthenticationMethod.ReadWrite.All", "GroupMember.ReadWrite.All"], probe
    assert probe["licences"] == {"P1": "absent", "P2": "absent", "Intune": "present"}, probe
    assert "group_reads" not in probe and "notes" not in probe, probe
    assert entra["enabled_groups"] == ["core", "identity", "security", "policy", "devices", "infra"], entra
    assert entra["password_writeback"] == {"value": "off", "source": "operator-declared"}, entra
    hidden = {h["tool"] + " " + h["action"]: h["reason"] for h in entra["hidden_actions"]}
    assert sorted(hidden) == ["entra_device managed_get", "entra_device managed_search",
                              "entra_policy auth_methods_policy", "entra_policy conditional_access", "entra_policy named_locations", "entra_policy security_defaults",
                              "entra_risk risk_detections", "entra_risk risky_users", "entra_role eligibility", "entra_signin search", "entra_user auth_methods", "entra_user registration"], sorted(hidden)
    # AuditLog.Read.All is granted: sign-ins are hidden for the licence alone.
    assert hidden["entra_signin search"] == "licence: needs P1", hidden
    assert ad["probe"]["bound"], ad
    assert {"dns": "corp.example.com", "netbios": "CORP", "dn": "DC=corp,DC=example,DC=com"} in ad["probe"]["domains"], ad
    assert ad["probe"]["reads"] == {"pso-read": "ok"}, ad["probe"]

    # ad_user search across a cursor: the 250 seeded users.
    page = call("ad_user", {"action": "search", "filter": "(sAMAccountName=vmuser*)"})
    assert len(page["results"]) == 200 and page.get("next_cursor"), {k: v for k, v in page.items() if k != "results"}
    brief = {"dn", "sAMAccountName", "userPrincipalName", "displayName", "mail", "enabled", "objectSid", "lastLogonTimestamp", "whenCreated"}
    assert set(page["results"][0]) <= brief, page["results"][0]
    rest = call("ad_user", {"action": "search", "filter": "(sAMAccountName=vmuser*)", "cursor": page["next_cursor"]})
    assert len(rest["results"]) == 50 and "next_cursor" not in rest, rest
    names = {r["sAMAccountName"] for r in page["results"] + rest["results"]}
    assert len(names) == 250, len(names)
    found = call("ad_user", {"action": "search", "query": "vmuser042"})
    assert [r["sAMAccountName"] for r in found["results"]] == ["vmuser042"], found

    # Gets resolved on the GC: by UPN, then by the SID that returned.
    by_upn = call("ad_user", {"action": "get", "id": "vmuser042@corp.example.com"})
    print("ad_user get", json.dumps(by_upn))
    assert by_upn["dn"].lower() == "${lib.toLower (userDN 42)}", by_upn
    assert by_upn["objectSid"].startswith("S-1-5-21-") and "userAccountControl" in by_upn and "whenChanged" in by_upn, by_upn
    by_sid = call("ad_user", {"action": "get", "id": by_upn["objectSid"]})
    assert by_sid["dn"] == by_upn["dn"], by_sid
    by_sam = call("ad_user", {"action": "get", "id": "CORP\\vmuser042", "fields": ["objectGUID"]})
    assert by_sam["dn"] == by_upn["dn"] and set(by_sam) == {"dn", "objectGUID"}, by_sam
    assert call("ad_object", {"action": "get", "id": by_sam["objectGUID"]})["dn"] == by_upn["dn"]

    # Counterparts by SID: vmuser042 is the stub's synced user, owned by the forest
    # (onPremisesSyncBehavior is refused, so onPremisesSyncEnabled says so).
    synced = {"id": "00000000-0000-0000-0000-000000000109", "source_of_authority": "forest", "source": "onPremisesSyncEnabled"}
    assert by_upn["counterpart"] == synced, by_upn
    assert "counterpart" not in by_sam, by_sam
    su = call("entra_user", {"action": "get", "id": synced["id"]})
    print("entra_user get synced", json.dumps(su))
    assert su["onPremisesSecurityIdentifier"] == by_upn["objectSid"], su
    assert su["counterpart"] == dict(synced, id=by_upn["dn"]), su
    assert call("ad_user", {"action": "get", "id": "vmuser043"})["counterpart"] == {"source_of_authority": "forest", "source": "no Entra object has its SID"}

    # Groups: a member count, direct members (one nested group), transitive members.
    team = call("ad_group", {"action": "get", "id": "vm-team"})
    assert team["memberCount"] == 6 and team["groupType"] == {"scope": "global", "type": "security"}, team
    direct = call("ad_group", {"action": "members", "id": "vm-team"})
    assert sorted(m.get("sAMAccountName") for m in direct["results"]) == ["vm-sub"] + ["vmuser00%d" % i for i in range(1, 6)], direct
    assert "next_cursor" not in direct, direct
    nested = call("ad_group", {"action": "members", "id": "vm-team", "transitive": True})
    assert sorted(m.get("sAMAccountName") for m in nested["results"]) == ["vm-sub"] + ["vmuser00%d" % i for i in range(1, 8)], nested

    # ad_api: a raw one-level search of the configuration partition.
    raw = call("ad_api", {"action": "search", "base": "CN=Partitions,CN=Configuration,${base}", "scope": "one",
                          "filter": "(objectClass=crossRef)", "attributes": ["nCName", "nETBIOSName"]})
    assert {"dn": "CN=CORP,CN=Partitions,CN=Configuration,${base}", "nCName": "${base}", "nETBIOSName": "CORP"} in raw["results"], raw

    # OUs: link counts, the tree under the domain heads and under vm-ou.
    ou = call("ad_ou", {"action": "search", "filter": "(name=vm-ou)"})["results"]
    assert [(o["name"], o["linkCount"]) for o in ou] == [("vm-ou", 2)], ou
    top = call("ad_ou", {"action": "tree"})["results"]
    assert {o["name"] for o in top} >= {"vm-ou", "Domain Controllers"}, top
    child = call("ad_ou", {"action": "tree", "id": "OU=vm-ou,${base}"})["results"]
    assert [(o["name"], o["gPOptions"]) for o in child] == [("vm-child", "1")], child

    # GPOs: get by GUID with where it is linked; links in inheritance order.
    a = call("ad_gpo", {"action": "get", "id": "${gpoA}"})
    print("ad_gpo get", json.dumps(a))
    assert a["displayName"] == "vm-gpo-a" and a["flags"] == "enabled" and "gPCFileSysPath" in a, a
    assert a["linked"] == [{"dn": "OU=vm-ou,${base}", "link_order": 2, "enforced": False, "disabled": False}], a
    assert call("ad_gpo", {"action": "get", "id": "${gpoB}"})["flags"] == "user_settings_disabled"
    links = call("ad_gpo", {"action": "links", "id": "OU=vm-ou,${base}"})
    print("ad_gpo links", json.dumps(links))
    assert [(x["displayName"], x["link_order"], x["enforced"]) for x in links["links"]] == [("vm-gpo-b", 1, True), ("vm-gpo-a", 2, False)], links
    assert [x["displayName"] for x in links["inheritance"]] == ["vm-gpo-b", "vm-gpo-a", "Default Domain Policy"], links
    assert links["inheritance"][2]["from"] == "${base}" and not links["block_inheritance"], links
    blocked = call("ad_gpo", {"action": "links", "id": "OU=vm-child,OU=vm-ou,${base}"})
    assert blocked["block_inheritance"] and blocked["links"] == [], blocked
    assert [(x["displayName"], x["from"]) for x in blocked["inheritance"]] == [("vm-gpo-b", "OU=vm-ou,${base}")], blocked
    dom = call("ad_gpo", {"action": "links", "domain": "corp.example.com"})
    assert [x["displayName"] for x in dom["inheritance"]] == ["Default Domain Policy"], dom

    # Password policy: the domain default, the PSO, and resultant policies that agree with them.
    default = call("ad_policy", {"action": "domain_default"})["results"]
    assert len(default) == 1 and default[0]["domain"] == "corp.example.com" and default[0]["minPwdLength"] == "7", default
    psos = call("ad_policy", {"action": "psos"})["results"]
    assert [(p["name"], p["msDS-PasswordSettingsPrecedence"], p["msDS-MinimumPasswordLength"], p["appliesToCount"]) for p in psos] == [("vm-pso", "10", "12", 1)], psos
    pso = call("ad_policy", {"action": "psos", "id": psos[0]["dn"]})
    assert pso["msDS-PSOAppliesTo"] == ["CN=vm-team,CN=Users,${base}"] and pso["msDS-LockoutThreshold"] == "5", pso
    via_team = call("ad_user", {"action": "resultant_policy", "id": "vmuser001"})
    assert via_team["source"] == "pso" and via_team["policy"] == pso, via_team
    plain = call("ad_user", {"action": "resultant_policy", "id": "vmuser100"})
    assert plain["source"] == "domain_default" and plain["policy"] == default[0], plain

    # Lockout: vm-locked was locked out by bad binds on the one DC before this session.
    lock = call("ad_user", {"action": "lockout", "id": "vm-locked"})
    print("ad_user lockout", json.dumps(lock))
    assert lock["locked_out"] and lock["lockoutTime"] and "LOCKOUT" in lock["msDS-User-Account-Control-Computed"], lock
    assert lock["lockoutTime_origin"]["dc"] == "${dcHost}" and lock["lockoutTime_origin"]["dsa"], lock
    assert [p["dc"] for p in lock["per_dc"]] == ["${dcHost}:636"] and int(lock["per_dc"][0]["badPwdCount"]) > 0, lock
    assert lock["per_dc"][0]["badPasswordTime"] and "_skipped" not in lock, lock

    # Topology: the one DC holds every role; Samba reports no msDS-Repl* attributes.
    assert call("ad_topology", {"action": "domains"})["results"] == [{"dns": "corp.example.com", "netbios": "CORP", "dn": "${base}"}]
    dcs = call("ad_topology", {"action": "dcs"})
    print("ad_topology dcs", json.dumps(dcs))
    assert dcs["results"] == [{"dNSHostName": "${dcHost}", "domain": "corp.example.com", "site": "Default-First-Site-Name",
                               "isGC": True, "isPDC": True, "reachable": True}], dcs
    assert call("ad_topology", {"action": "sites"})["results"] == [{"name": "Default-First-Site-Name", "subnets": 0, "dcs": 1}]
    fsmo = call("ad_topology", {"action": "fsmo"})["results"]
    assert [(r["role"], r["dc"]) for r in fsmo] == [(r, "${dcHost}") for r in ("schema", "domain_naming", "pdc", "rid", "infrastructure")], fsmo
    repl = call("ad_topology", {"action": "replication"})
    print("ad_topology replication", json.dumps(repl))
    assert [r["dc"] for r in repl["results"]] == ["${dcHost}:636"] and repl["results"][0]["inbound"] == [], repl
    assert call("ad_topology", {"action": "trusts"})["results"] == []
    assert call("ad_topology", {"action": "subnets"})["results"] == []

    # Entra reads. A search across the stub's two pages, the second throttled once.
    first = call("entra_user", {"action": "search"})
    rest = call("entra_user", {"action": "search", "cursor": first["next_cursor"]})
    assert [u["displayName"] for u in first["results"] + rest["results"]] == ["Entra User 1", "Entra User 2", "Entra User 3"], (first, rest)
    assert "next_cursor" not in rest, rest
    eu = call("entra_user", {"action": "get", "id": "entra-user2@example.com"})
    print("entra_user get", json.dumps(eu))
    assert eu["id"] == "00000000-0000-0000-0000-000000000102", eu
    assert eu["assignedLicenses"] == [{"skuId": "00000000-0000-0000-0000-0000000000c1", "skuPartNumber": "EXCHANGESTANDARD"}], eu
    assert "signInActivity" in eu["_omitted"], eu
    assert eu["counterpart"] == {"source_of_authority": "tenant", "source": "cloud-only: no onPremisesSecurityIdentifier"}, eu
    members = call("entra_group", {"action": "members", "id": "00000000-0000-0000-0000-000000000401"})["results"]
    assert [(m["@odata.type"], m.get("userPrincipalName"), m.get("deviceId")) for m in members] == [
        ("#microsoft.graph.user", "entra-user1@example.com", None),
        ("#microsoft.graph.device", None, "00000000-0000-0000-0000-000000000301")], members
    assert call("entra_device", {"action": "search"})["results"][0]["displayName"] == "entra-device1"
    beta = call("entra_api", {"action": "get", "path": "/beta/organization"})
    assert beta["results"][0]["displayName"] == "Example Org" and "beta" in beta["_unstable"], beta
    assert "_unstable" not in call("entra_api", {"action": "get", "path": "/v1.0/organization"})

    # Credentials ending within 30 days: only the app's "soon" secret, without its hint.
    exp = call("entra_app", {"action": "expiring_credentials", "days": 30})
    print("entra_app expiring_credentials", json.dumps(exp))
    assert [(r["kind"], r["displayName"], r["credential"], r["credentialName"]) for r in exp["results"]] == [("app", "vm-app", "password", "soon")], exp
    assert "hint" not in exp["results"][0], exp
    org = call("entra_org", {"action": "info"})
    print("entra_org info", json.dumps(org))
    assert org["displayName"] == "Example Org" and org["onPremisesSyncEnabled"] is True, org
    assert org["password_writeback"]["value"] == "off" and org["password_writeback"]["source"] == "operator-declared", org
    # The audit hint: the seeded Enable password writeback event.
    assert org["password_writeback"]["audit_hint"]["value"] == "enabled", org

    # The directory audit log, cut to the brief; a filter on the activity.
    audit = call("entra_audit", {"action": "search"})
    print("entra_audit search", json.dumps(audit))
    assert [a["activityDisplayName"] for a in audit["results"]] == ["Enable password writeback for directory", "Add user"], audit
    assert audit["results"][1]["targetResources"] == [{"displayName": "Entra User 1"}] and "id" not in audit["results"][1], audit
    added = call("entra_audit", {"action": "search", "filter": "activityDisplayName eq 'Add user'"})["results"]
    assert [a["initiatedBy"]["user"]["userPrincipalName"] for a in added] == ["admin@example.com"], added

    # Writes: the server runs with --capabilities ad-account-state,ad-passwords,ad-group-membership,ad-objects,ad-delete,
    # ad-gpo-links,ad-password-policy,entra-account-state,entra-credentials,entra-group-membership.
    assert ad["enabled_capabilities"] == ["ad-account-state", "ad-passwords", "ad-group-membership", "ad-objects", "ad-delete",
                                          "ad-gpo-links", "ad-password-policy"], ad
    assert entra["enabled_capabilities"] == ["entra-account-state", "entra-credentials", "entra-group-membership"], entra
    api = next(t for t in listed["result"]["tools"] if t["name"] == "ad_api")
    assert api["inputSchema"]["properties"]["action"]["enum"] == ["search", "modify", "add", "delete", "rename"], api
    user = next(t for t in listed["result"]["tools"] if t["name"] == "ad_user")
    assert user["inputSchema"]["properties"]["action"]["enum"][-7:] == ["disable", "enable", "unlock", "must_change", "set_expiry", "reset_password", "create"], user
    # A raw delete is routed to the first-class action.
    why = refused("ad_api", {"action": "delete", "dn": "${userDN 43}", "reason": "vm-test"})
    assert "call ad_object delete instead" in why, why
    # Protected: a Domain Admins member, though the bind account could write it.
    why = refused("ad_user", {"action": "disable", "id": "vmuser200", "reason": "vm-test protected"})
    print("ad_user disable vmuser200", why)
    assert "protected target" in why, why
    # Raw: a password write is routed to the first-class action.
    why = refused("ad_api", {"action": "modify", "dn": "${userDN 43}", "reason": "vm-test raw",
                             "changes": [{"op": "replace", "attribute": "unicodePwd", "values": ["x"]}]})
    print("ad_api modify unicodePwd", why)
    assert "call ad_user reset_password instead" in why, why
    assert "reason is required" in refused("ad_user", {"action": "disable", "id": "vmuser042"})
    # vmuser042 (synced, so Entra follows on the next cycle): disable, then enable.
    for action, enabled in (("disable", False), ("enable", True)):
        w = call("ad_user", {"action": action, "id": "vmuser042", "reason": "vm-test " + action + " vmuser042"})
        print("ad_user", action, json.dumps(w))
        assert w["dc"] == "${dcHost}:636" and not w.get("fallback"), w
        assert w["sync"].startswith("the change reaches its Entra counterpart " + synced["id"]), w
        assert call("ad_user", {"action": "get", "id": "vmuser042", "fields": ["enabled"]})["enabled"] is enabled

    # ad-passwords: a Domain Admins member is refused; a confirm mismatch sends nothing.
    why = refused("ad_user", {"action": "reset_password", "id": "vmuser200", "confirm": "vmuser200", "reason": "vm-test reset protected"})
    print("ad_user reset_password vmuser200", why)
    assert "protected target" in why, why
    before = call("ad_user", {"action": "get", "id": "vm-reset", "fields": ["pwdLastSet"]})["pwdLastSet"]
    why = refused("ad_user", {"action": "reset_password", "id": "vm-reset", "confirm": "vmuser200", "reason": "vm-test reset mismatch"})
    assert "confirm must be the target's name exactly" in why, why
    assert call("ad_user", {"action": "get", "id": "vm-reset", "fields": ["pwdLastSet"]})["pwdLastSet"] == before
    # A one-target reset, without must-change so the new password binds; the test script binds with it.
    w = call("ad_user", {"action": "reset_password", "id": "vm-reset", "confirm": "vm-reset", "must_change": False,
                         "reason": "vm-test reset vm-reset"})
    assert w["dc"] == "${dcHost}:636" and w["must_change"] is False and len(w["password"]) >= 20, {k: v for k, v in w.items() if k != "password"}
    with open("/tmp/vm-reset-password", "w") as f:
        f.write(w["password"])
    # ad-group-membership: vmuser100 in and out of vm-team.
    for action, present in (("add_members", True), ("remove_members", False)):
        w = call("ad_group", {"action": action, "id": "vm-team", "members": ["vmuser100"], "reason": "vm-test " + action})
        print("ad_group", action, json.dumps(w))
        assert w["members"] == ["${userDN 100}"] and w["dc"] == "${dcHost}:636", w
        dns = [m["dn"] for m in call("ad_group", {"action": "members", "id": "vm-team"})["results"]]
        assert ("${userDN 100}" in dns) is present, dns

    # ad-objects: create, edit, rename and move a user; an off-allowlist raw edit is refused.
    w = call("ad_user", {"action": "create", "parent": "CN=Users,${base}", "name": "vm-new", "upn": "vm-new@corp.example.com",
                         "attributes": {"displayName": "VM New"}, "reason": "vm-test create vm-new"})
    print("ad_user create", json.dumps({k: v for k, v in w.items() if k != "password"}))
    assert w["dn"] == "CN=vm-new,CN=Users,${base}" and w["must_change"] is True and len(w["password"]) >= 20, w["dn"]
    with open("/tmp/vm-new-password", "w") as f:
        f.write(w["password"])
    new = call("ad_user", {"action": "get", "id": "vm-new", "fields": ["enabled", "displayName", "pwdLastSet", "userPrincipalName"]})
    assert new["enabled"] is True and new["displayName"] == "VM New" and new["pwdLastSet"] in (None, "1601-01-01T00:00:00Z"), new
    call("ad_object", {"action": "edit", "id": "vm-new", "attributes": {"title": "Tester", "displayName": ""}, "reason": "vm-test edit"})
    new = call("ad_user", {"action": "get", "id": "vm-new", "fields": ["title", "displayName"]})
    assert new.get("title") == "Tester" and "displayName" not in new, new
    why = refused("ad_api", {"action": "modify", "dn": "CN=vm-new,CN=Users,${base}", "reason": "vm-test raw spn",
                             "changes": [{"op": "add", "attribute": "servicePrincipalName", "values": ["HTTP/vm-new"]}]})
    print("ad_api modify servicePrincipalName", why)
    assert "not a write this server makes" in why, why
    call("ad_api", {"action": "modify", "dn": "CN=vm-new,CN=Users,${base}", "reason": "vm-test raw edit",
                    "changes": [{"op": "replace", "attribute": "description", "values": ["raw"]}]})
    w = call("ad_object", {"action": "rename", "id": "vm-new", "name": "vm-renamed", "reason": "vm-test rename"})
    assert call("ad_user", {"action": "get", "id": "vm-new", "fields": ["description"]}) == {"dn": "CN=vm-renamed,CN=Users,${base}", "description": "raw"}
    w = call("ad_object", {"action": "move", "id": "vm-new", "parent": "OU=vm-ou,${base}", "reason": "vm-test move"})
    print("ad_object move", json.dumps(w))
    assert "warning" not in w, w
    assert call("ad_user", {"action": "get", "id": "vm-new", "fields": ["name"]})["dn"] == "CN=vm-renamed,OU=vm-ou,${base}"

    # ad-delete: a confirm mismatch sends nothing; delete, then restore from search_deleted.
    assert "confirm must be" in refused("ad_object", {"action": "delete", "id": "vm-new", "confirm": "vm-renamed", "reason": "vm-test delete mismatch"})
    w = call("ad_object", {"action": "delete", "id": "vm-new", "confirm": "vm-new", "reason": "vm-test delete"})
    print("ad_object delete", json.dumps(w))
    assert "sync" in w["warning"], w
    refused("ad_user", {"action": "get", "id": "vm-new"})
    gone = call("ad_object", {"action": "search_deleted", "filter": "(sAMAccountName=vm-new)"})["results"]
    print("search_deleted", json.dumps(gone))
    assert len(gone) == 1 and gone[0]["lastKnownParent"] == "OU=vm-ou,${base}", gone
    w = call("ad_object", {"action": "restore", "id": gone[0]["dn"], "reason": "vm-test restore"})
    print("ad_object restore", json.dumps(w))
    assert w["restored_as"] == "CN=vm-renamed,OU=vm-ou,${base}", w
    assert call("ad_user", {"action": "get", "id": "vm-new", "fields": ["objectGUID"]})["objectGUID"] == gone[0]["objectGUID"]

    # ad-password-policy: applying vm-pso to Domain Admins is refused, and vm-pso still applies to vm-team alone.
    vm_pso = "CN=vm-pso,CN=Password Settings Container,CN=System,${base}"
    why = refused("ad_policy", {"action": "apply", "id": vm_pso, "applies_to": ["Domain Admins"], "reason": "vm-test pso protected"})
    print("ad_policy apply Domain Admins", why)
    assert "protected target" in why, why
    assert call("ad_policy", {"action": "psos", "id": vm_pso})["msDS-PSOAppliesTo"] == ["CN=vm-team,CN=Users,${base}"]

    # ad-gpo-links: unlink vm-gpo-a from vm-ou, link it back enforced; links reflects each. The DC OU is refused.
    why = refused("ad_gpo", {"action": "link", "id": "OU=Domain Controllers,${base}", "gpo": "${gpoA}", "reason": "vm-test link dc ou"})
    print("ad_gpo link Domain Controllers", why)
    assert "protected target" in why, why
    w = call("ad_gpo", {"action": "unlink", "id": "OU=vm-ou,${base}", "gpo": "${gpoA}", "reason": "vm-test unlink"})
    print("ad_gpo unlink", json.dumps(w))
    assert [x["gpo"].lower() for x in w["links"]] == ["${lib.toLower (gpoDN gpoB)}"] and w["dc"] == "${dcHost}:636", w
    w = call("ad_gpo", {"action": "link", "id": "OU=vm-ou,${base}", "gpo": "${gpoA}", "enforced": True, "reason": "vm-test link"})
    print("ad_gpo link", json.dumps(w))
    links = call("ad_gpo", {"action": "links", "id": "OU=vm-ou,${base}"})
    assert [(x["displayName"], x["link_order"], x["enforced"]) for x in links["links"]] == [("vm-gpo-b", 1, True), ("vm-gpo-a", 2, True)], links
    assert [x["displayName"] for x in links["inheritance"]] == ["vm-gpo-b", "vm-gpo-a", "Default Domain Policy"], links

    # entra-account-state: the synced user's disable is refused and routed to AD; a cloud user's goes through.
    why = refused("entra_user", {"action": "disable", "id": synced["id"], "reason": "vm-test entra synced"})
    print("entra_user disable synced", why)
    assert "call ad_user disable or enable on " + by_upn["dn"] in why, why
    w = call("entra_user", {"action": "disable", "id": "entra-user3@example.com", "reason": "vm-test entra disable"})
    print("entra_user disable", json.dumps(w))
    assert w["id"] == "00000000-0000-0000-0000-000000000103" and w["endpoint"] == "PATCH /v1.0/users/entra-user3@example.com", w
    assert call("entra_user", {"action": "get", "id": w["id"]})["accountEnabled"] is False

    # entra-credentials, with writeback declared off: the synced user's reset is refused and routed to AD; a cloud user's goes through.
    why = refused("entra_user", {"action": "reset_password", "id": synced["id"], "confirm": "synced-user@example.com", "reason": "vm-test entra reset synced"})
    print("entra_user reset_password synced", why)
    assert "call ad_user reset_password on " + by_upn["dn"] in why and "--entra-password-writeback" in why, why
    w = call("entra_user", {"action": "reset_password", "id": "entra-user2@example.com", "confirm": "entra-user2@example.com", "reason": "vm-test entra reset"})
    assert w["endpoint"] == "PATCH /v1.0/users/entra-user2@example.com" and w["must_change"] is True and len(w["password"]) >= 20, w
    with open("/tmp/vm-entra-password", "w") as fh:
        fh.write(w["password"])
    print("ok")
  '';

  root0400 = argument: {
    user = "root";
    group = "root";
    mode = "0400";
    inherit argument;
  };
in
pkgs.testers.runNixOSTest {
  name = "microsoft-directory-mcp-vm";

  nodes.machine =
    { ... }:
    {
      imports = [ self.nixosModules.microsoft-directory-mcp ];

      virtualisation.memorySize = 2048;
      # /etc/hosts gets dc1.corp.example.com, the name on Samba's certificate.
      networking.hostName = "dc1";
      networking.domain = "corp.example.com";

      environment.systemPackages = [
        pkgs.curl
        pkgs.openldap
        session
      ];

      systemd.services.samba-dc = {
        description = "Samba AD DC";
        wantedBy = [ "multi-user.target" ];
        path = [
          pkgs.samba4Full
          pkgs.gnused
        ];
        preStart = ''
          if [ ! -e /var/lib/samba-dc/private/sam.ldb ]; then
            # Not Samba's auto-generated certificates: their serial is time(NULL)'s
            # little-endian bytes, negative in DER half the time, and Go rejects those.
            mkdir -p ${tlsDir} && cd ${tlsDir}
            ${openssl} req -x509 -newkey rsa:2048 -nodes -subj /CN=vm-test-ca -days 2 -keyout ca.key -out ca.pem
            ${openssl} req -newkey rsa:2048 -nodes -subj /CN=${dcHost} -keyout key.pem -out req.csr
            printf 'subjectAltName=DNS:${dcHost}\nextendedKeyUsage=serverAuth\n' > ext.cnf
            ${openssl} x509 -req -in req.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile ext.cnf -out cert.pem
            chmod 0600 key.pem ca.key
            samba-tool domain provision --server-role=dc --use-rfc2307 \
              --dns-backend=SAMBA_INTERNAL --realm=${realm} --domain=CORP \
              --adminpass='${adminPass}' --targetdir=/var/lib/samba-dc --host-ip=127.0.0.1
            # provision --option does not persist this; the old password must stop binding at once.
            sed -i '/\[global\]/a old password allowed period = 0' ${smbConf}
            sed -i '/\[global\]/a tls keyfile = ${tlsDir}/key.pem\n\ttls certfile = ${tlsDir}/cert.pem\n\ttls cafile = ${tlsDir}/ca.pem' ${smbConf}
            samba-tool user create ${bindUser} '${bindPass}' -s ${smbConf}
            # The bind account may write (and reset passwords of) objects under CN=Users; the seed objects added next inherit it.
            svcSid=$(ldbsearch -H /var/lib/samba-dc/private/sam.ldb '(sAMAccountName=${bindUser})' objectSid | sed -n 's/^objectSid: //p')
            samba-tool dsacl set -H /var/lib/samba-dc/private/sam.ldb -s ${smbConf} \
              --objectdn='CN=Users,${base}' --sddl="(A;CI;RPWPCR;;;$svcSid)"
            ldbadd -H /var/lib/samba-dc/private/sam.ldb ${seedLdif}
            # It may also create, delete and move objects there and under OU=vm-ou, see and reanimate deleted objects.
            samba-tool dsacl set -H /var/lib/samba-dc/private/sam.ldb -s ${smbConf} \
              --objectdn='CN=Users,${base}' --sddl="(A;CI;CCDCSD;;;$svcSid)"
            samba-tool dsacl set -H /var/lib/samba-dc/private/sam.ldb -s ${smbConf} \
              --objectdn='OU=vm-ou,${base}' --sddl="(A;CI;RPWPCCDCSD;;;$svcSid)"
            # dsacl can't re-read the deleted-objects container, so its descriptor is replaced whole.
            printf 'dn: CN=Deleted Objects,${base}\nchangetype: modify\nreplace: nTSecurityDescriptor\nnTSecurityDescriptor: %s\n' \
              "O:SYG:SYD:PAI(A;;CCDCLCSWRPWPSDRCWDWO;;;SY)(A;;LCRP;;;BA)(A;CI;RPLCWPSD;;;$svcSid)" \
              | ldbmodify -H /var/lib/samba-dc/private/sam.ldb --controls=show_deleted:1
            samba-tool dsacl set -H /var/lib/samba-dc/private/sam.ldb -s ${smbConf} \
              --objectdn='${base}' --sddl="(OA;;CR;45ec5156-db7e-47bb-b53f-dbeb2d03c40f;;$svcSid)"
            # Writes read tokenGroups to find protected-group members; the bind account needs this group for that.
            samba-tool group addmembers 'Windows Authorization Access Group' ${bindUser} -s ${smbConf}
            # A protected target: a Domain Admins member, though writable by the bind account.
            samba-tool group addmembers 'Domain Admins' vmuser200 -s ${smbConf}
            ldbsearch -H /var/lib/samba-dc/private/sam.ldb '(sAMAccountName=vmuser042)' objectSid \
              | sed -n 's/^objectSid: //p' > ${syncedSid}
            grep -q '^S-1-5-21-' ${syncedSid}
            # PSOs are unreadable to the bind account by default; delegate it first so vm-pso inherits it.
            samba-tool dsacl set -H /var/lib/samba-dc/private/sam.ldb -s ${smbConf} \
              --objectdn='CN=Password Settings Container,CN=System,${base}' --sddl='(A;CI;RPLCLORC;;;AU)'
            samba-tool domain passwordsettings pso create vm-pso 10 --min-pwd-length=12 --account-lockout-threshold=5 -s ${smbConf}
            samba-tool domain passwordsettings pso apply vm-pso vm-team -s ${smbConf}
            # vm-locked, locked out by bad binds before the session, under a domain lockout threshold of 3.
            samba-tool domain passwordsettings set --account-lockout-threshold=3 -s ${smbConf}
            samba-tool user create vm-locked '${lockedPass}' -s ${smbConf}
            # vm-reset, whose password ad_user reset_password replaces.
            samba-tool user create vm-reset '${resetPass}' -s ${smbConf}
          fi
        '';
        serviceConfig = {
          ExecStart = "${pkgs.samba4Full}/sbin/samba --foreground --no-process-group -s ${smbConf}";
          # "samba" too: samba mkdirs the compiled-in /var/lib/samba/ntp_signd and exits without it.
          StateDirectory = [
            "samba-dc"
            "samba"
          ];
        };
      };

      # Wait for LDAPS, then publish the CA where the DynamicUser service can read it.
      systemd.services.samba-dc-ca = {
        description = "Publish the Samba DC's CA";
        requires = [ "samba-dc.service" ];
        after = [ "samba-dc.service" ];
        serviceConfig.Type = "oneshot";
        serviceConfig.RemainAfterExit = true;
        script = ''
          until ${openssl} s_client -connect 127.0.0.1:636 -CAfile ${tlsDir}/ca.pem \
            -verify_return_error </dev/null >/dev/null 2>&1; do sleep 0.5; done
          install -m 0444 ${tlsDir}/ca.pem /run/samba-ca.pem
        '';
      };

      # The Entra certificate: a 0400 root key+cert for the server, and the
      # certificate alone for the stub to verify assertions against.
      systemd.services.entra-fixture = {
        description = "Generate the Entra certificate fixture";
        serviceConfig.Type = "oneshot";
        serviceConfig.RemainAfterExit = true;
        script = ''
          cd "$(mktemp -d)"
          ${lib.getExe pkgs.openssl} req -x509 -newkey rsa:2048 -nodes -subj /CN=vm-test -days 2 \
            -keyout key.pem -out cert.pem
          umask 0377
          cat key.pem cert.pem > /run/entra-cert.pem
          install -m 0444 cert.pem ${certPublic}
        '';
      };

      systemd.services.stub-graph = {
        description = "Stub Microsoft Graph";
        wantedBy = [ "multi-user.target" ];
        requires = [ "entra-fixture.service" ];
        after = [ "entra-fixture.service" ];
        serviceConfig.ExecStart = lib.getExe stub;
      };

      systemd.services.microsoft-directory-mcp = {
        requires = [
          "samba-dc-ca.service"
          "entra-fixture.service"
          "stub-graph.service"
        ];
        after = [
          "samba-dc-ca.service"
          "entra-fixture.service"
          "stub-graph.service"
        ];
      };

      # Root-only 0400 files, the shape sops-nix and agenix produce.
      systemd.tmpfiles.settings."10-microsoft-directory-mcp" = {
        "/run/ad-bind-password".f = root0400 bindPass;
        "/run/mcp-bearer".f = root0400 httpToken;
      };

      services.microsoft-directory-mcp = {
        enable = true;
        logLevel = "debug";
        extraArgs = [
          "--capabilities"
          "ad-account-state,ad-passwords,ad-group-membership,ad-objects,ad-delete,ad-gpo-links,ad-password-policy,entra-account-state,entra-credentials,entra-group-membership"
        ];
        http.authTokenFile = "/run/mcp-bearer";
        ad = {
          forest = "corp.example.com";
          bindUser = "${bindUser}@corp.example.com";
          bindPasswordFile = "/run/ad-bind-password";
          caFile = "/run/samba-ca.pem";
          dcs = [ dcHost ];
        };
        entra = {
          inherit tenant clientId;
          certFile = "/run/entra-cert.pem";
          loginUrl = "http://127.0.0.1:${toString stubPort}";
          graphUrl = "http://127.0.0.1:${toString stubPort}";
          passwordWriteback = "off";
        };
      };
    };

  testScript = ''
    machine.wait_for_unit("microsoft-directory-mcp.service", timeout=120)
    machine.wait_for_open_port(${toString mcpPort})

    with subtest("lock out vm-locked with bad binds"):
        for _ in range(3):
            machine.fail("LDAPTLS_CACERT=/run/samba-ca.pem ldapwhoami -x -H ldaps://${dcHost} -D vm-locked@corp.example.com -w wrong")

    with subtest("a full MCP session: ad_status over LDAPS, entra_status with a verified assertion"):
        print(machine.succeed("mcp-session"))

    with subtest("the stub verified the client assertion and saw the issued bearer"):
        machine.succeed("grep -qxF ${clientId} /tmp/stub-verified")
        machine.fail("test -e /tmp/stub-rejected")
        machine.succeed("grep -qxF 'Bearer ${accessToken}' /tmp/stub-bearers")

    with subtest("the Entra user search waited out the stub's 429"):
        machine.succeed("grep -q /v1.0/users /tmp/stub-throttled")

    with subtest("/healthz answers without the bearer"):
        machine.succeed("curl -fsS http://127.0.0.1:${toString mcpPort}/healthz")

    with subtest("the MCP endpoint refuses a missing or wrong bearer"):
        for h in ("", "-H 'Authorization: Bearer wrong'"):
            code = machine.succeed(f"curl -s -o /dev/null -w '%{{http_code}}' -X POST {h} http://127.0.0.1:${toString mcpPort}/mcp").strip()
            assert code == "401", code

    with subtest("the bind password is in neither argv nor the journal"):
        pid = machine.succeed("systemctl show -p MainPID --value microsoft-directory-mcp.service").strip()
        machine.fail(f"tr '\\0' '\\n' < /proc/{pid}/cmdline | grep -qF '${bindPass}'")
        journal = machine.succeed("journalctl -o cat --no-pager -u microsoft-directory-mcp.service")
        assert "starting" in journal, journal
        for secret in ("${bindPass}", "${httpToken}", "${accessToken}"):
            assert secret not in journal, f"{secret} leaked into the journal"

    with subtest("the writes are in the audit log with their reasons and outcomes"):
        journal = machine.succeed("journalctl -o cat --no-pager -u microsoft-directory-mcp.service")
        for line in ('reason="vm-test disable vmuser042"', 'reason="vm-test enable vmuser042"'):
            assert any(line in x and "outcome=ok" in x and "dc=${dcHost}:636" in x and "capability=ad-account-state" in x
                       for x in journal.splitlines()), line
        assert any('reason="vm-test protected"' in x and 'outcome="not sent"' in x for x in journal.splitlines()), journal
        assert any('reason="vm-test entra disable"' in x and "outcome=ok" in x and "capability=entra-account-state" in x
                   for x in journal.splitlines()), journal

    with subtest("the reset password binds, the old one does not, and the journal never has it"):
        pw = machine.succeed("cat /tmp/vm-reset-password")
        bind = "LDAPTLS_CACERT=/run/samba-ca.pem ldapwhoami -x -H ldaps://${dcHost} -D vm-reset@corp.example.com -w "
        machine.succeed(bind + f"'{pw}'")
        machine.fail(bind + "'${resetPass}'")
        journal = machine.succeed("journalctl -o cat --no-pager -u microsoft-directory-mcp.service")
        assert pw not in journal, "the reset password leaked into the journal"
        assert any('reason="vm-test reset vm-reset"' in x and "outcome=ok" in x and "capability=ad-passwords" in x
                   for x in journal.splitlines()), journal
        assert any('reason="vm-test add_members"' in x and "outcome=ok" in x and "capability=ad-group-membership" in x
                   for x in journal.splitlines()), journal

    with subtest("the created user's password is not in the journal, and each object write is audited"):
        pw = machine.succeed("cat /tmp/vm-new-password")
        journal = machine.succeed("journalctl -o cat --no-pager -u microsoft-directory-mcp.service")
        assert pw not in journal, "the created user's password leaked into the journal"
        for reason, cap in (("create vm-new", "ad-objects"), ("edit", "ad-objects"), ("raw edit", "ad-objects"), ("rename", "ad-objects"),
                            ("move", "ad-objects"), ("delete", "ad-delete"), ("restore", "ad-delete")):
            assert any(f'reason="vm-test {reason}"' in x and "outcome=ok" in x and f"capability={cap}" in x
                       for x in journal.splitlines()), reason

    with subtest("the Entra reset password is in neither the journal nor the audit log, and the reset is audited"):
        pw = machine.succeed("cat /tmp/vm-entra-password")
        journal = machine.succeed("journalctl -o cat --no-pager -u microsoft-directory-mcp.service")
        assert pw not in journal, "the Entra reset password leaked into the journal"
        assert any('reason="vm-test entra reset"' in x and "outcome=ok" in x and "capability=entra-credentials" in x
                   for x in journal.splitlines()), journal
        assert any('reason="vm-test entra reset synced"' in x and 'outcome="not sent"' in x for x in journal.splitlines()), journal

    with subtest("the stub recorded the cloud users' writes and no write to the synced user"):
        writes = machine.succeed("cat /tmp/stub-writes").splitlines()
        assert writes == ["PATCH /v1.0/users/entra-user3@example.com", "PATCH /v1.0/users/entra-user2@example.com"], writes
  '';
}
