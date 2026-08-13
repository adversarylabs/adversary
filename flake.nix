{
  description = "Adversary CLI development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            (final: prev: {
              go_1_26 = prev.go_1_26.overrideAttrs {
                version = "1.26.6";
                src = prev.fetchurl {
                  url = "https://go.dev/dl/go1.26.6.src.tar.gz";
                  hash = "sha256-oHIcVMaIkBRI13rZs+x+p8R0cwdV/4kTgukuy5P/LLE=";
                };
              };
            })
          ];
        };
        go = pkgs.go_1_26;
        buildGoModule = pkgs.buildGoModule.override { inherit go; };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            go
            pkgs.gnumake
            pkgs.git
            pkgs.nodejs_22
            pkgs.actionlint
            pkgs.shellcheck
            pkgs.gnutar
            pkgs.gzip
            pkgs.curl
            pkgs.xz
          ];

          shellHook = ''
            if [ "$(${go}/bin/go env GOVERSION)" != "go1.26.6" ]; then
              echo "expected Go 1.26.6, got $(${go}/bin/go env GOVERSION)" >&2
              return 1
            fi
          '';
        };

        packages.default = buildGoModule {
          pname = "adversary";
          version = "dev";
          src = self;
          # The TypeScript template has a directory named vendor; use the Go
          # module fetcher explicitly instead of mistaking it for `go mod vendor`.
          proxyVendor = true;
          vendorHash = "sha256-6Z4aU/q9rMCU2nSiGp+XIRTWtEtSW1U+7A9KmYHrCvo=";
          subPackages = [ "." ];
          preCheck = ''
            export HOME="$TMPDIR/home"
            mkdir -p "$HOME"
          '';
          ldflags = [
            "-X github.com/adversarylabs/adversary/internal/version.Version=dev"
          ];
        };
      });
}
