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
                version = "1.26.5";
                src = prev.fetchurl {
                  url = "https://go.dev/dl/go1.26.5.src.tar.gz";
                  hash = "sha256-SVvkvIcXasVnOS5bQRar2YRm0z17SdQedkzMaXay3EI=";
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
          ];

          shellHook = ''
            if [ "$(${go}/bin/go env GOVERSION)" != "go1.26.5" ]; then
              echo "expected Go 1.26.5, got $(${go}/bin/go env GOVERSION)" >&2
              return 1
            fi
          '';
        };

        packages.default = buildGoModule {
          pname = "adversary";
          version = "0.1.0";
          src = self;
          vendorHash = null;
        };
      });
}
