{
  description = "MCP server for Active Directory and Entra ID";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      forAllSystems = lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
      ];
      pkgsFor = system: nixpkgs.legacyPackages.${system};
    in
    {
      overlays.default = import ./overlay.nix;

      nixosModules = {
        microsoft-directory-mcp =
          { pkgs, ... }:
          {
            imports = [ ./modules/microsoft-directory-mcp.nix ];
            services.microsoft-directory-mcp.package =
              lib.mkDefault
                self.packages.${pkgs.stdenv.hostPlatform.system}.microsoft-directory-mcp;
          };
        default = self.nixosModules.microsoft-directory-mcp;
      };

      packages = forAllSystems (system: rec {
        microsoft-directory-mcp = (pkgsFor system).callPackage ./pkgs/microsoft-directory-mcp.nix { };
        default = microsoft-directory-mcp;
      });

      checks = forAllSystems (system: {
        # Runs the Go test suite in checkPhase.
        package = self.packages.${system}.microsoft-directory-mcp;
        # Boots a VM with a Samba AD DC and a stub Graph.
        vm = import ./tests/vm.nix {
          inherit self;
          pkgs = pkgsFor system;
        };
      });

      formatter = forAllSystems (system: (pkgsFor system).nixfmt-tree);

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.go
              pkgs.gopls
              pkgs.gotools
              pkgs.nixfmt
              pkgs.openssl
            ];
            env.CGO_ENABLED = "0";
            # /tmp is a small tmpfs on the dev machines; keep Go's build
            # scratch and cache off it.
            shellHook = ''
              export GOCACHE="$HOME/.cache/go-build"
              export GOTMPDIR="$PWD/.gotmp"
              mkdir -p "$GOTMPDIR"
            '';
          };
        }
      );
    };
}
