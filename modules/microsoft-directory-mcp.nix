{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    mkIf
    mkOption
    mkEnableOption
    types
    optional
    optionals
    literalExpression
    ;
  cfg = config.services.microsoft-directory-mcp;
  # Keep in step with config.Groups and config.Capabilities; the
  # module-flags-sync check compares them with the binary's --help.
  groups = [
    "core"
    "identity"
    "security"
    "policy"
    "devices"
    "infra"
  ];
  # The write capability map, docs/adr/0001.
  capabilities = [
    "ad-account-state"
    "ad-passwords"
    "ad-group-membership"
    "ad-objects"
    "ad-delete"
    "ad-gpo-links"
    "ad-password-policy"
    "entra-account-state"
    "entra-credentials"
    "entra-group-membership"
    "entra-objects"
    "entra-delete"
    "entra-licenses"
    "entra-devices"
    "entra-risk"
    "intune-device-actions"
    "intune-retire-wipe"
  ];
  # "host:port" or "[v6]:port" -> [ host port ], as Go's net.SplitHostPort.
  v6 = builtins.match "\\[([^]]+)]:([0-9]+)" cfg.http.addr;
  addrParts = if v6 != null then v6 else builtins.match "([^]:[]*):([0-9]+)" cfg.http.addr;
  host = lib.elemAt addrParts 0;
  port = lib.elemAt addrParts 1;
  validAddr = addrParts != null && lib.toInt port >= 1 && lib.toInt port <= 65535;
  # config.go's loopback(), minus IPv4-mapped and expanded IPv6 forms.
  isLoopback =
    host == "localhost"
    || host == "::1"
    || builtins.match "127\\.[0-9]+\\.[0-9]+\\.[0-9]+" host != null;
  inStore = p: p != null && lib.hasPrefix builtins.storeDir p;
  absolute = p: p == null || lib.hasPrefix "/" p;
  str = types.nullOr types.str;
  opt =
    flag: description:
    mkOption {
      type = str;
      default = null;
      description = "${description} (`--${flag}`).";
    };
  # A null option adds nothing; anything else adds --flag value.
  arg =
    flag: v:
    optionals (v != null) [
      "--${flag}"
      v
    ];
  adOn = cfg.ad.forest != null;
  entraOn = cfg.entra.tenant != null;

  # Secret files reach the process as systemd credentials: %d is the
  # credentials directory, so the path on argv names no secret.
  args = [
    "--http"
    "--addr"
    cfg.http.addr
    "--path"
    cfg.http.path
    "--log-level"
    cfg.logLevel
    "--request-timeout"
    cfg.requestTimeout
    "--tool-groups"
    (lib.concatStringsSep "," cfg.toolGroups)
  ]
  ++ optionals (cfg.capabilities != [ ]) [
    "--capabilities"
    (lib.concatStringsSep "," cfg.capabilities)
  ]
  ++ optional cfg.noProbe "--no-probe"
  ++ optionals adOn (
    arg "ad-forest" cfg.ad.forest
    ++ arg "ad-bind-user" cfg.ad.bindUser
    ++ [
      "--ad-bind-password-file"
      "%d/ad-bind-password"
      "--ad-tls"
      cfg.ad.tls
    ]
    ++ optionals (cfg.ad.caFile != null) [
      "--ad-ca-file"
      "%d/ad-ca"
    ]
    ++ optional cfg.ad.insecureSkipVerify "--ad-insecure-skip-verify"
    ++ arg "ad-site" cfg.ad.site
    ++ optionals (cfg.ad.dcs != [ ]) [
      "--ad-dc"
      (lib.concatStringsSep "," cfg.ad.dcs)
    ]
    ++ optionals (cfg.ad.protectedGroups != [ ]) [
      "--protected-groups"
      (lib.concatStringsSep "," cfg.ad.protectedGroups)
    ]
  )
  ++ optionals entraOn (
    arg "entra-tenant" cfg.entra.tenant
    ++ arg "entra-client-id" cfg.entra.clientId
    ++ [
      "--entra-cert-file"
      "%d/entra-cert"
      "--entra-cloud"
      cfg.entra.cloud
      "--entra-password-writeback"
      cfg.entra.passwordWriteback
    ]
    ++ arg "entra-login-url" cfg.entra.loginUrl
    ++ arg "entra-graph-url" cfg.entra.graphUrl
  )
  ++ optionals (cfg.http.authTokenFile != null) [
    "--http-auth-token-file"
    "%d/http-auth-token"
  ]
  ++ cfg.extraArgs;
in
{
  options.services.microsoft-directory-mcp = {
    enable = mkEnableOption "the Microsoft directory MCP server as a streamable HTTP systemd service";

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ../pkgs/microsoft-directory-mcp.nix { };
      defaultText = literalExpression "pkgs.microsoft-directory-mcp";
      description = "The microsoft-directory-mcp package.";
    };

    installCli = mkOption {
      type = types.bool;
      default = cfg.enable;
      defaultText = literalExpression "config.services.microsoft-directory-mcp.enable";
      description = ''
        Put the binary on the system PATH. Set this with enable = false on a
        workstation that only spawns the server over stdio from an MCP client.
      '';
    };

    ad = {
      forest = opt "ad-forest" "Forest root DNS name. Setting it turns the AD side on";
      bindUser = opt "ad-bind-user" "Bind account UPN";
      bindPasswordFile = opt "ad-bind-password-file" "Runtime path to the bind password, passed via systemd `LoadCredential`";
      tls = mkOption {
        type = types.enum [
          "ldaps"
          "starttls"
        ];
        default = "ldaps";
        description = "TLS mode (`--ad-tls`). Plain LDAP is never used.";
      };
      caFile = opt "ad-ca-file" "Runtime path to a PEM CA bundle added to the system roots, passed via systemd `LoadCredential`";
      insecureSkipVerify = mkOption {
        type = types.bool;
        default = false;
        description = "Do not verify domain controller certificates (`--ad-insecure-skip-verify`).";
      };
      site = opt "ad-site" "AD site whose site-scoped SRV records discovery uses";
      dcs = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "dc1.corp.example.com" ];
        description = "Static domain controller list, host or host:port (`--ad-dc`); empty means DNS SRV discovery.";
      };
      protectedGroups = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "CORP\\Tier0 Admins" ];
        description = "Extra groups, `DOMAIN\\name` or SID, whose members, direct or nested, writes never touch (`--protected-groups`).";
      };
    };

    entra = {
      tenant = opt "entra-tenant" "Tenant ID or domain. Setting it turns the Entra side on";
      clientId = opt "entra-client-id" "App registration client ID";
      certFile = opt "entra-cert-file" "Runtime path to a PEM file with the RSA private key and certificate, passed via systemd `LoadCredential`";
      cloud = mkOption {
        type = types.enum [
          "global"
          "usgov"
          "usgovdod"
          "china"
        ];
        default = "global";
        description = "National cloud (`--entra-cloud`).";
      };
      passwordWriteback = mkOption {
        type = types.enum [
          "on"
          "off"
          "unknown"
        ];
        default = "unknown";
        description = ''
          Whether password writeback is on, as you declare it (`--entra-password-writeback`).
          entra_status reports it as operator-declared: app-only Graph cannot detect it.
          Check Password reset > On-premises integration in the Entra admin center.
        '';
      };
      loginUrl = opt "entra-login-url" "Login base URL override, for tests; only with the global cloud";
      graphUrl = opt "entra-graph-url" "Graph base URL override, for tests; only with the global cloud";
    };

    http = {
      addr = mkOption {
        type = types.str;
        default = "127.0.0.1:8235";
        description = "Listen address as host:port (`--addr`). A non-loopback host requires authTokenFile.";
      };
      path = mkOption {
        type = types.str;
        default = "/mcp";
        description = "URL path of the MCP endpoint (`--path`).";
      };
      authTokenFile = opt "http-auth-token-file" "Runtime path to the bearer token HTTP clients must send, passed via systemd `LoadCredential`";
    };

    toolGroups = mkOption {
      type = types.listOf (types.enum groups);
      default = groups;
      description = "Tool groups to enable (`--tool-groups`). core is always on.";
    };
    capabilities = mkOption {
      type = types.listOf (types.enum capabilities);
      default = [ ];
      example = [ "ad-account-state" ];
      description = "Write capabilities to enable (`--capabilities`), all off by default; see docs/adr/0001.";
    };
    noProbe = mkOption {
      type = types.bool;
      default = false;
      description = "Skip the startup probe that hides actions the server can't perform, and show everything (`--no-probe`).";
    };

    requestTimeout = mkOption {
      type = types.str;
      default = "30s";
      description = "Per-request timeout (`--request-timeout`).";
    };
    logLevel = mkOption {
      type = types.enum [
        "debug"
        "info"
        "warn"
        "error"
      ];
      default = "info";
      description = "Log verbosity (`--log-level`).";
    };
    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Extra command-line arguments. Never put a secret here.";
    };
  };

  config = lib.mkMerge [
    (mkIf cfg.installCli { environment.systemPackages = [ cfg.package ]; })

    (mkIf cfg.enable {
      assertions = [
        {
          assertion = adOn || entraOn;
          message = "services.microsoft-directory-mcp: set ad.forest, entra.tenant or both.";
        }
        {
          assertion = !adOn || cfg.ad.bindPasswordFile != null;
          message = "services.microsoft-directory-mcp.ad.bindPasswordFile is required with ad.forest.";
        }
        {
          assertion = !entraOn || cfg.entra.certFile != null;
          message = "services.microsoft-directory-mcp.entra.certFile is required with entra.tenant.";
        }
        {
          assertion = !adOn || cfg.ad.bindUser != null;
          message = "services.microsoft-directory-mcp.ad.bindUser is required with ad.forest.";
        }
        {
          assertion = !entraOn || cfg.entra.clientId != null;
          message = "services.microsoft-directory-mcp.entra.clientId is required with entra.tenant.";
        }
        {
          assertion =
            !entraOn
            || cfg.entra.cloud == "global"
            || (cfg.entra.loginUrl == null && cfg.entra.graphUrl == null);
          message = "services.microsoft-directory-mcp: entra.loginUrl and entra.graphUrl only work with entra.cloud = \"global\".";
        }
        {
          assertion = lib.all absolute [
            cfg.ad.bindPasswordFile
            cfg.ad.caFile
            cfg.entra.certFile
            cfg.http.authTokenFile
          ];
          message = "services.microsoft-directory-mcp: ad.bindPasswordFile, ad.caFile, entra.certFile and http.authTokenFile must be absolute paths.";
        }
        {
          assertion = validAddr;
          message = "services.microsoft-directory-mcp.http.addr must be host:port or [v6]:port with a port from 1 to 65535, got ${cfg.http.addr}.";
        }
        {
          assertion = !validAddr || isLoopback || cfg.http.authTokenFile != null;
          message = "services.microsoft-directory-mcp.http.addr is ${cfg.http.addr} (not loopback) without http.authTokenFile; the server refuses to start unauthenticated on a network address.";
        }
        {
          assertion = lib.hasPrefix "/" cfg.http.path;
          message = "services.microsoft-directory-mcp.http.path must begin with a slash.";
        }
        {
          assertion = lib.all (p: !(inStore p)) [
            cfg.ad.bindPasswordFile
            cfg.entra.certFile
            cfg.http.authTokenFile
          ];
          message = "services.microsoft-directory-mcp: secret files must not live in ${builtins.storeDir}, which is world-readable. Use sops-nix, agenix or a root-owned 0400 file.";
        }
      ];

      warnings =
        optional (adOn && cfg.ad.insecureSkipVerify)
          "services.microsoft-directory-mcp.ad.insecureSkipVerify is true: domain controller certificates are not verified, so the bind password can go to an impostor.";

      systemd.services.microsoft-directory-mcp = {
        description = "Microsoft directory MCP server";
        documentation = [ "https://github.com/lcleveland/microsoft-directory-mcp" ];
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig = {
          Type = "exec";
          ExecStart = "${lib.getExe cfg.package} ${lib.escapeShellArgs args}";
          Restart = "on-failure";
          RestartSec = 5;
          LoadCredential =
            optional adOn "ad-bind-password:${cfg.ad.bindPasswordFile}"
            ++ optional (adOn && cfg.ad.caFile != null) "ad-ca:${cfg.ad.caFile}"
            ++ optional entraOn "entra-cert:${cfg.entra.certFile}"
            ++ optional (cfg.http.authTokenFile != null) "http-auth-token:${cfg.http.authTokenFile}";
          DynamicUser = true;
          AmbientCapabilities = [ "" ];
          CapabilityBoundingSet = [ "" ];
          DevicePolicy = "closed";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          PrivateDevices = true;
          PrivateTmp = true;
          PrivateUsers = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectControlGroups = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectKernelModules = true;
          ProtectKernelTunables = true;
          ProtectProc = "invisible";
          ProtectSystem = "strict";
          RemoveIPC = true;
          # AF_NETLINK: Go's pure resolver reads interface addresses.
          RestrictAddressFamilies = [
            "AF_INET"
            "AF_INET6"
            "AF_NETLINK"
          ];
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = [
            "@system-service"
            "~@privileged"
            "~@resources"
          ];
          UMask = "0077";
          SocketBindDeny = "any";
          SocketBindAllow = mkIf validAddr "tcp:${port}";
        };
      };
    })
  ];
}
