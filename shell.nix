{ pkgs ? import <nixpkgs> {} }:
let haskellPackages =
      pkgs.recurseIntoAttrs
        (pkgs.haskellPackages.override {
           extension = self: super:
                       {
                         RFC1751 = self.callPackage ./nix/RFC1751.nix {};
                         thisPackage = haskellPackages.callPackage (import ./default.nix) {};
                       };
         });
in pkgs.lib.overrideDerivation haskellPackages.thisPackage (old: {
   buildInputs = old.buildInputs ++ [
     haskellPackages.cabalInstall
     # (2)
   ];})
