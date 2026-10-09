# nixpkgs.overlays = [ microsoft-directory-mcp.overlays.default ]; gives
# pkgs.microsoft-directory-mcp. Not needed for the NixOS module, which
# defaults to this flake's build.
final: _prev: {
  microsoft-directory-mcp = final.callPackage ./pkgs/microsoft-directory-mcp.nix { };
}
