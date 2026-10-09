# VM test: the real binary against a real Samba AD DC and a stub Graph, on
# one node with three units (docs/research/vm-test-stubs.md):
#
#   samba-dc                 Samba AD DC, provisioned in preStart; LDAPS with
#                            Samba's auto-generated CA
#   stub-graph               stdlib Python Graph: v2.0 token endpoint that
#                            verifies the client assertion, and /organization
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
  tenant = "00000000-0000-0000-0000-0000000000aa";
  clientId = "00000000-0000-0000-0000-0000000000bb";
  httpToken = "mcp-http-bearer";
  smbConf = "/var/lib/samba-dc/etc/smb.conf";
  # The certificate half of the Entra fixture, readable by the stub.
  certPublic = "/run/entra-cert-public.pem";

  # Routes are (method, path) -> handler; later issues add to ROUTES and SEED.
  stub = pkgs.writers.writePython3Bin "stub-graph" { flakeIgnore = [ "E501" ]; } ''
    import base64
    import hashlib
    import http.server
    import json
    import os
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
    ACCESS_TOKEN = "issued-graph-access-token"

    SEED = {
        "organization": [{
            "id": TENANT,
            "displayName": "Example Org",
            "onPremisesSyncEnabled": True,
            "onPremisesLastSyncDateTime": "2026-01-01T00:00:00Z",
        }],
    }


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


    ROUTES = {
        ("POST", TOKEN_PATH): token,
        ("GET", "/v1.0/organization"): organization,
    }
    UNAUTHENTICATED = {TOKEN_PATH}


    class Handler(http.server.BaseHTTPRequestHandler):
        def reply(self, status, payload):
            body = json.dumps(payload).encode()
            self.send_response(status)
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
                bearer = self.headers.get("Authorization", "")
                record("bearers", bearer)
                if bearer != "Bearer " + ACCESS_TOKEN:
                    return self.error(401, "InvalidAuthenticationToken", "bad bearer")
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
    ids = iter(range(1, 100))


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


    _, listed = post({"jsonrpc": "2.0", "id": next(ids), "method": "tools/list"}, session)
    tools = sorted(t["name"] for t in listed["result"]["tools"])
    assert tools == ["ad_status", "entra_status"], tools

    ad = call("ad_status", {})
    print("ad_status", json.dumps(ad))
    assert ad["bound"] and ad["tls"] == "ldaps" and "tls_warning" not in ad, ad
    assert ad["dc"] == "${dcHost}:636", ad
    assert ad["root_dse"]["default_naming_context"] == "DC=corp,DC=example,DC=com", ad
    assert "CN=Configuration,DC=corp,DC=example,DC=com" in ad["root_dse"]["naming_contexts"], ad

    entra = call("entra_status", {})
    print("entra_status", json.dumps(entra))
    assert entra["authenticated"] and entra["cloud"] == "global", entra
    assert entra["on_premises_sync_enabled"] is True, entra
    assert entra["on_premises_last_sync"] == "2026-01-01T00:00:00Z", entra
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
            samba-tool domain provision --server-role=dc --use-rfc2307 \
              --dns-backend=SAMBA_INTERNAL --realm=${realm} --domain=CORP \
              --adminpass='${adminPass}' --targetdir=/var/lib/samba-dc --host-ip=127.0.0.1
            # provision --option does not persist this; the old password must stop binding at once.
            sed -i '/\[global\]/a old password allowed period = 0' ${smbConf}
            samba-tool user create ${bindUser} '${bindPass}' -s ${smbConf}
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

      # Samba writes its CA on first start. Wait for it and LDAPS, then
      # publish the CA where the DynamicUser service can read it.
      systemd.services.samba-dc-ca = {
        description = "Publish the Samba DC's CA";
        requires = [ "samba-dc.service" ];
        after = [ "samba-dc.service" ];
        serviceConfig.Type = "oneshot";
        serviceConfig.RemainAfterExit = true;
        script = ''
          ca=/var/lib/samba-dc/private/tls/ca.pem
          # Non-empty is not enough: samba may still be writing it, and a
          # half-written CA restart-loops the server forever.
          until ${lib.getExe pkgs.openssl} x509 -in $ca -noout 2>/dev/null \
            && ${pkgs.netcat}/bin/nc -z 127.0.0.1 636; do sleep 0.5; done
          install -m 0444 $ca /run/samba-ca.pem.tmp
          mv /run/samba-ca.pem.tmp /run/samba-ca.pem
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
        };
      };
    };

  testScript = ''
    machine.wait_for_unit("microsoft-directory-mcp.service", timeout=120)
    machine.wait_for_open_port(${toString mcpPort})

    with subtest("a full MCP session: ad_status over LDAPS, entra_status with a verified assertion"):
        print(machine.succeed("mcp-session"))

    with subtest("the stub verified the client assertion and saw the issued bearer"):
        machine.succeed("grep -qxF ${clientId} /tmp/stub-verified")
        machine.fail("test -e /tmp/stub-rejected")
        machine.succeed("grep -qxF 'Bearer issued-graph-access-token' /tmp/stub-bearers")

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
        for secret in ("${bindPass}", "${httpToken}", "issued-graph-access-token"):
            assert secret not in journal, f"{secret} leaked into the journal"
  '';
}
