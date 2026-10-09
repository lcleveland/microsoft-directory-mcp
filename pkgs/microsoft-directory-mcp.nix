# Static Go binary. Refresh vendorHash whenever go.mod/go.sum change:
#   nix build .#microsoft-directory-mcp 2>&1 | grep 'got:'
{
  lib,
  buildGoModule,
  versionCheckHook,
}:

buildGoModule (finalAttrs: {
  pname = "microsoft-directory-mcp";
  version = "0.1.0";

  # Only the Go tree, so editing docs or Nix does not rebuild the binary.
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../go.mod
      ../go.sum
      ../cmd
      ../internal
    ];
  };

  vendorHash = "sha256-Uz3AdZ7GKxcbg+5rwzRzZS2RreS81Ht+nSibYD8bvZQ=";

  subPackages = [ "cmd/microsoft-directory-mcp" ];
  env.CGO_ENABLED = 0;

  ldflags = [
    "-s"
    "-w"
    "-X"
    "github.com/lcleveland/microsoft-directory-mcp/internal/version.Version=${finalAttrs.version}"
  ];

  # subPackages also narrows what checkPhase tests; unset it so the whole
  # ./internal suite runs (all hermetic, httptest on loopback).
  preCheck = ''
    unset subPackages
  '';

  nativeInstallCheckInputs = [ versionCheckHook ];
  versionCheckProgramArg = "--version";
  doInstallCheck = true;

  meta = {
    description = "MCP server for Active Directory and Entra ID";
    homepage = "https://github.com/lcleveland/microsoft-directory-mcp";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
    mainProgram = "microsoft-directory-mcp";
  };
})
