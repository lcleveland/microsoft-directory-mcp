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
  inStore = p: p != null && lib.hasPrefix builtins.storeDir p;
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
  ++ optional (!cfg.probe) "--no-probe"
  ++ optionals adOn (
    arg "ad-forest" cfg.ad.forest
    ++ arg "ad-bind-user" cfg.ad.bindUser
    ++ [
      "--ad-bind-password-file"
      "%d/ad-bind-password"
      "--ad-tls"
      cfg.ad.tls
    ]
    ++ arg "ad-ca-file" cfg.ad.caFile
    ++ optional cfg.ad.insecureSkipVerify "--ad-insecure-skip-verify"
    ++ arg "ad-site" cfg.ad.site
    ++ optionals (cfg.ad.dcs != [ ]) [
      "--ad-dc"
      (lib.concatStringsSep "," cfg.ad.dcs)
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
      caFile = opt "ad-ca-file" "PEM CA bundle added to the system roots";
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
      loginUrl = opt "entra-login-url" "Login base URL override, for tests";
      graphUrl = opt "entra-graph-url" "Graph base URL override, for tests";
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
      type = types.listOf (
        types.enum [
          "core"
          "identity"
          "security"
          "policy"
          "devices"
          "infra"
        ]
      );
      default = [
        "core"
        "identity"
        "security"
        "policy"
        "devices"
        "infra"
      ];
      description = "Tool groups to enable (`--tool-groups`). core is always on.";
    };
    probe = mkOption {
      type = types.bool;
      default = true;
      description = "Run the startup probe that hides actions the server can't perform. false passes `--no-probe` and shows everything.";
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
          assertion = lib.all (p: !(inStore p)) [
            cfg.ad.bindPasswordFile
            cfg.entra.certFile
            cfg.http.authTokenFile
          ];
          message = "services.microsoft-directory-mcp: secret files must not live in ${builtins.storeDir}, which is world-readable. Use sops-nix, agenix or a root-owned 0400 file.";
        }
      ];

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
            ++ optional entraOn "entra-cert:${cfg.entra.certFile}"
            ++ optional (cfg.http.authTokenFile != null) "http-auth-token:${cfg.http.authTokenFile}";
          DynamicUser = true;
          # ponytail: minimal; the full sibling hardening lands with the Nix lane issue.
          NoNewPrivileges = true;
          PrivateTmp = true;
          ProtectHome = true;
          ProtectSystem = "strict";
          UMask = "0077";
        };
      };
    })
  ];
}
