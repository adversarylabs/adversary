{
  description = "Adversary CLI development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.go_1_22
            pkgs.gnumake
            pkgs.git
          ];
        };

        packages.default = pkgs.buildGoModule {
          pname = "adversary";
          version = "0.1.0";
          src = self;
          vendorHash = null;
        };
      });
}
