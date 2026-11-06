# Development shell: `nix-shell`, then `stack build` (Stack uses its own GHC).
{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  buildInputs = with pkgs; [ stack secp256k1 pkg-config gmp zlib jq ];
}
