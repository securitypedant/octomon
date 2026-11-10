# The octomon derivation, in the shape nixpkgs wants (callPackage arguments,
# nothing flake-specific), so the same file can be sent upstream as
# pkgs/by-name/oc/octomon/package.nix with `src` swapped for fetchFromGitHub
# and `cargoHash` for the lock file.
{
  lib,
  rustPlatform,
  pkg-config,
  aws-lc,
}:

rustPlatform.buildRustPackage (finalAttrs: {
  pname = "octomon";
  version = (lib.importTOML ../../Cargo.toml).package.version;

  # The checkout itself. Cargo.toml's `include` list already keeps the
  # published crate to source, so the same filter is right here: it drops
  # the website, the test rig, media and the debug binary at the repo root.
  src = lib.fileset.toSource {
    root = ../..;
    fileset = lib.fileset.unions [
      ../../Cargo.toml
      ../../Cargo.lock
      ../../build.rs
      ../../src
      ../../resources
      ../../README.md
      ../../PRIVILEGES.md
      ../../SECURITY.md
      ../../LICENSE-MIT
      ../../LICENSE-APACHE
    ];
  };

  cargoLock.lockFile = ../../Cargo.lock;

  # rustls' crypto provider is aws-lc-rs; nixpkgs' Rust hook asks aws-lc-sys
  # to link the packaged AWS-LC (AWS_LC_SYS_USE_SYSTEM) instead of building
  # its own with CMake, and it finds it through pkg-config.
  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ aws-lc ];

  # The test suite probes the host's interfaces, resolvers and gateway; in
  # the build sandbox there is no network to find, so several tests cannot
  # pass there. CI runs them on every platform.
  doCheck = false;

  meta = {
    description = "btop-style terminal dashboard for your network: latency, bandwidth, Wi-Fi and DNS, with an analysis that names the failing layer";
    homepage = "https://octomon.dev";
    changelog = "https://octomon.dev/changelog";
    license = with lib.licenses; [
      mit
      asl20
    ];
    mainProgram = "octomon";
    platforms = lib.platforms.unix;
    maintainers = [ ];
  };
})
