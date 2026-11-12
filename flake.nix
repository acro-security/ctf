{
  description = "ctf environments";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  # pwndbg ships its own flake and a binary cache.  The revision is pinned so
  # `nix flake update` does not silently change the debugger under us.
  inputs.pwndbg = {
    url = "github:pwndbg/pwndbg/9760ac8f1346d142857cffc933995cd6fca34dff";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  nixConfig = {
    extra-substituters = [ "https://pwndbg.cachix.org" ];
    extra-trusted-public-keys = [
      "pwndbg.cachix.org-1:HhtIpP7j73SnuzLgobqqa8LVTng5Qi36sQtNt79cD3k="
    ];
  };

  outputs = { self, nixpkgs, pwndbg }:
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
              binutils
              bun
              checksec
              curl
              gef
              hexyl
              just
              lua5_4
              python3
              python3Packages.pwntools
              radare2
              sbcl
              unzip
              uv
              wireguard-tools
              xxd
            ] ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
              gdb
              ghidra
              iproute2
              iptables
              ltrace
              openresolv
              procps
              pwndbg.packages.${system}.pwndbg
              strace
            ];

            UV_PYTHON = "${pkgs.python3}/bin/python3";
            UV_PYTHON_DOWNLOADS = "never";
            SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";

            # GDB tries debuginfod for separate debug info on every launch.
            # With no debuginfod client/mirror configured this only produces
            # slow, failing downloads, and pwndbg aborts commands such as
            # vis-heap-chunks when a library's debug file cannot be found.
            DEBUGINFOD_URLS = "";

            # Ghidra and other Java/Swing apps render a blank window under
            # niri's xwayland-satellite without this workaround.
            _JAVA_AWT_WM_NONREPARENTING = "1";

            shellHook = ''
              echo "CTF development environment"
              echo "  bun:    $(bun --version)"
              echo "  lua:    $(lua -v 2>&1)"
              echo "  sbcl:   $(sbcl --version)"
              echo "  uv:     $(uv --version)"
              echo "  python: $(python3 --version)"
              echo "  gdb:    $(gdb --version | head -1)"
              echo "  debuggers: pwndbg, gef (both wrap gdb)"
            '';
          };
        });
    };
}
