# Module evaluation checks: no VM, just the generated unit.
{
  pkgs,
  self,
  lib,
}:
let
  evalModule =
    module:
    (lib.nixosSystem {
      inherit (pkgs.stdenv.hostPlatform) system;
      modules = [
        self.nixosModules.microsoft-directory-mcp
        {
          services.microsoft-directory-mcp.package = lib.mkForce (
            pkgs.writeShellScriptBin "microsoft-directory-mcp" "exit 0"
          );
          boot.loader.grub.enable = false;
          fileSystems."/" = {
            device = "none";
            fsType = "tmpfs";
          };
          system.stateVersion = lib.trivial.release;
        }
        module
      ];
    });

  failed = config: map (a: a.message) (builtins.filter (a: !a.assertion) config.assertions);

  ad = {
    forest = "corp.example.com";
    bindUser = "svc-mcp@corp.example.com";
    bindPasswordFile = "/persist/secrets/ad-bind-password";
  };
  entra = {
    tenant = "00000000-0000-0000-0000-0000000000aa";
    clientId = "00000000-0000-0000-0000-0000000000bb";
    certFile = "/persist/secrets/entra-cert.pem";
  };

  # The AD side alone unless extra says otherwise.
  base = extra: {
    services.microsoft-directory-mcp = lib.recursiveUpdate {
      enable = true;
      inherit ad;
    } extra;
  };

  # Evaluates cleanly and the generated unit passes the grep checks.
  unitCheck =
    name: extra: checks:
    let
      config = (evalModule (base extra)).config;
      broken = failed config;
      svc = config.systemd.services.microsoft-directory-mcp;
    in
    assert broken == [ ] || throw "${name}: ${lib.concatStringsSep "; " broken}";
    pkgs.runCommand "microsoft-directory-mcp-${name}" { } ''
      cat > cmd <<'EOF'
      ${svc.serviceConfig.ExecStart}
      EOF
      cat > env <<'EOF'
      ${lib.concatStringsSep "\n" (lib.mapAttrsToList (k: v: "${k}=${v}") svc.environment)}
      EOF
      cat > creds <<'EOF'
      ${lib.concatStringsSep "\n" svc.serviceConfig.LoadCredential}
      EOF
      cat > bind <<'EOF'
      ${svc.serviceConfig.SocketBindAllow}
      EOF
      check() { grep -qF -- "$1" "$2" || { echo "missing from $2: $1"; cat "$2"; exit 1; }; }
      refute() { if grep -qF -- "$1" "$2"; then echo "unexpected in $2: $1"; cat "$2"; exit 1; fi; }
      ${checks}
      touch $out
    '';

  # Evaluation must trip an assertion containing `want`.
  mustFail =
    name: extra: want:
    let
      broken = failed (evalModule (base extra)).config;
    in
    assert
      lib.any (lib.hasInfix want) broken
      || throw "${name}: expected assertion '${want}', got: ${toString broken}";
    pkgs.runCommand "microsoft-directory-mcp-${name}" { } "touch $out";

  warns =
    name: extra: want:
    let
      config = (evalModule (base extra)).config;
    in
    assert lib.any (lib.hasInfix want) config.warnings || throw "${name}: no warning '${want}'";
    pkgs.runCommand "microsoft-directory-mcp-${name}" { } "touch $out";

  evaluated = evalModule { };
  opts = evaluated.options.services.microsoft-directory-mcp;
  enumValues = o: o.type.nestedTypes.elemType.functor.payload.values;
  clouds = opts.entra.cloud.type.functor.payload.values;
in
{
  module-eval = unitCheck "module-eval" { } ''
    check "--http" cmd
    check "--addr 127.0.0.1:8235" cmd
    check "--path /mcp" cmd
    check "--ad-forest corp.example.com" cmd
    check "--ad-bind-user svc-mcp@corp.example.com" cmd
    check "--ad-bind-password-file %d/ad-bind-password" cmd
    check "--ad-tls ldaps" cmd
    check "--tool-groups core,identity,security,policy,devices,infra" cmd
    check "--log-level info" cmd
    check "ad-bind-password:/persist/secrets/ad-bind-password" creds
    check "tcp:8235" bind
    refute "/persist/secrets" cmd
    refute "/persist/secrets" env
    refute "--entra-" cmd
    refute "entra-cert" creds
    refute "http-auth-token" creds
    refute "--capabilities" cmd
    refute "--no-probe" cmd
    refute "--ad-insecure-skip-verify" cmd
  '';

  module-full =
    unitCheck "module-full"
      {
        ad = {
          tls = "starttls";
          caFile = "/etc/ssl/corp-ca.pem";
          site = "Default-First-Site-Name";
          dcs = [
            "dc1.corp.example.com"
            "dc2.corp.example.com:3269"
          ];
        };
        entra = entra // {
          passwordWriteback = "on";
        };
        capabilities = [
          "ad-account-state"
          "entra-licenses"
        ];
        toolGroups = [ "identity" ];
        noProbe = true;
        logLevel = "debug";
        requestTimeout = "1m";
        http = {
          addr = "[::]:9000";
          path = "/directory";
          authTokenFile = "/run/secrets/bearer";
        };
        extraArgs = [ "--stdio=false" ];
      }
      ''
        check "--ad-tls starttls" cmd
        check "--ad-ca-file %d/ad-ca" cmd
        check "ad-ca:/etc/ssl/corp-ca.pem" creds
        check "--ad-site Default-First-Site-Name" cmd
        check "--ad-dc dc1.corp.example.com,dc2.corp.example.com:3269" cmd
        check "--entra-tenant 00000000-0000-0000-0000-0000000000aa" cmd
        check "--entra-client-id 00000000-0000-0000-0000-0000000000bb" cmd
        check "--entra-cert-file %d/entra-cert" cmd
        check "entra-cert:/persist/secrets/entra-cert.pem" creds
        check "--entra-cloud global" cmd
        check "--entra-password-writeback on" cmd
        refute "--entra-login-url" cmd
        refute "--entra-graph-url" cmd
        check "--capabilities ad-account-state,entra-licenses" cmd
        check "--tool-groups identity" cmd
        check "--no-probe" cmd
        check "--log-level debug" cmd
        check "--request-timeout 1m" cmd
        check "--addr '[::]:9000'" cmd
        check "--path /directory" cmd
        check "--http-auth-token-file %d/http-auth-token" cmd
        check "http-auth-token:/run/secrets/bearer" creds
        check "--stdio=false" cmd
        refute "/run/secrets/bearer" cmd
        refute "/persist/secrets" cmd
        check "tcp:9000" bind
      '';

  # The Entra side alone: no AD flag or credential, even with AD files set.
  module-entra-only =
    unitCheck "module-entra-only"
      {
        ad = {
          forest = null;
          caFile = "/etc/ssl/corp-ca.pem";
        };
        entra = entra // {
          cloud = "usgov";
        };
      }
      ''
        check "--entra-cloud usgov" cmd
        refute "--ad-" cmd
        refute "ad-bind-password" creds
        refute "ad-ca" creds
        check "entra-cert:/persist/secrets/entra-cert.pem" creds
      '';

  module-test-urls =
    unitCheck "module-test-urls"
      {
        entra = entra // {
          loginUrl = "http://127.0.0.1:9444";
          graphUrl = "http://127.0.0.1:9444";
        };
      }
      ''
        check "--entra-login-url http://127.0.0.1:9444" cmd
        check "--entra-graph-url http://127.0.0.1:9444" cmd
      '';

  # installCli alone puts the CLI on PATH for stdio clients and runs no unit.
  module-cli-only =
    let
      config =
        (evalModule {
          services.microsoft-directory-mcp.installCli = true;
        }).config;
    in
    assert failed config == [ ] || throw "cli-only: ${toString (failed config)}";
    assert !(config.systemd.services ? microsoft-directory-mcp) || throw "cli-only: unit defined";
    assert
      lib.any (p: (p.name or "") == "microsoft-directory-mcp") config.environment.systemPackages
      || throw "cli-only: package not installed";
    pkgs.runCommand "microsoft-directory-mcp-cli-only" { } "touch $out";

  # The module's capabilities, groups and clouds must match the binary's flags.
  module-flags-sync = pkgs.runCommand "microsoft-directory-mcp-flags-sync" { } ''
    help=$(${
      lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.microsoft-directory-mcp
    } --help 2>&1 || true)
    echo "$help" | grep -qF -- "(${lib.concatStringsSep ", " (enumValues opts.capabilities)});" \
      || { echo "capabilities differ from the binary's:"; echo "$help"; exit 1; }
    echo "$help" | grep -qF -- "\"${lib.concatStringsSep "," (enumValues opts.toolGroups)}\"" \
      || { echo "tool groups differ from the binary's:"; echo "$help"; exit 1; }
    echo "$help" | grep -qF -- "${lib.concatStringsSep "|" (lib.sort lib.lessThan clouds)} " \
      || { echo "clouds differ from the binary's:"; echo "$help"; exit 1; }
    touch $out
  '';

  # Every flag in the binary's --help must appear in the README.
  readme-flags = pkgs.runCommand "microsoft-directory-mcp-readme-flags" { } ''
    help=$(${
      lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.microsoft-directory-mcp
    } --help 2>&1 || true)
    flags=$(echo "$help" | grep -oE '^  -[a-z-]+' | sed 's/^  -/--/')
    [ -n "$flags" ] || { echo "no flags parsed from --help:"; echo "$help"; exit 1; }
    for f in $flags; do
      grep -qF -- "\`$f\`" ${self}/README.md || { echo "README.md does not document $f"; exit 1; }
    done
    touch $out
  '';

  module-insecure-warn = warns "insecure-warn" {
    ad.insecureSkipVerify = true;
  } "ad.insecureSkipVerify is true";

  module-no-side = mustFail "no-side" { ad.forest = null; } "set ad.forest, entra.tenant or both";
  module-no-bind-password = mustFail "no-bind-password" {
    ad.bindPasswordFile = null;
  } "ad.bindPasswordFile is required";
  module-no-bind-user = mustFail "no-bind-user" { ad.bindUser = null; } "ad.bindUser is required";
  module-no-cert = mustFail "no-cert" {
    entra = entra // {
      certFile = null;
    };
  } "entra.certFile is required";
  module-no-client-id = mustFail "no-client-id" {
    entra = entra // {
      clientId = null;
    };
  } "entra.clientId is required";
  module-cloud-and-url = mustFail "cloud-and-url" {
    entra = entra // {
      cloud = "china";
      graphUrl = "https://graph.example.test";
    };
  } "only work with entra.cloud";
  module-secret-in-store = mustFail "secret-in-store" {
    ad.bindPasswordFile = "${builtins.storeDir}/abc-secret";
  } "world-readable";
  module-token-in-store = mustFail "token-in-store" {
    http.authTokenFile = "${builtins.storeDir}/abc-token";
  } "world-readable";
  module-relative-secret = mustFail "relative-secret" {
    ad.bindPasswordFile = "secrets/bind";
  } "must be absolute paths";
  module-open-listener = mustFail "open-listener" {
    http.addr = "0.0.0.0:8235";
  } "without http.authTokenFile";
  module-open-listener-any = mustFail "open-listener-any" {
    http.addr = ":8235";
  } "without http.authTokenFile";
  module-loopback-lookalike = mustFail "loopback-lookalike" {
    http.addr = "127.example.test:8235";
  } "without http.authTokenFile";
  module-bad-addr = mustFail "bad-addr" { http.addr = "localhost"; } "host:port";
  module-bare-v6-addr = mustFail "bare-v6-addr" { http.addr = "::1:8235"; } "host:port";
  module-port-zero = mustFail "port-zero" { http.addr = "127.0.0.1:0"; } "host:port";
  module-bad-path = mustFail "bad-path" { http.path = "mcp"; } "must begin with a slash";
}
