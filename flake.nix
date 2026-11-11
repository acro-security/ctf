{
  description = "ctf environments";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in {
          default = pkgs.mkShell {
            packages = with pkgs; [
              curl
              just
              lua5_4
              python3
              sbcl
              uv
              wireguard-tools
              xxd
            ] ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
              iproute2
              iptables
              openresolv
              procps
            ];

            UV_PYTHON = "${pkgs.python3}/bin/python3";
            UV_PYTHON_DOWNLOADS = "never";
            SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";

            shellHook = ''
              echo "CTF development environment"
              echo "  lua:    $(lua -v 2>&1)"
              echo "  sbcl:   $(sbcl --version)"
              echo "  uv:     $(uv --version)"
              echo "  python: $(python3 --version)"
            '';
          };
        });
    };
}
