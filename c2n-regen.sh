#!/bin/bash
cabal2nix ./. > default.nix
#cabal2nix cabal://RFC1751 > nix/RFC1751.nix
cabal2nix --rev=cb6b960262ce1a7f598a3d08d00a2c348dfed91e git://github.com/np/RFC1751.git > nix/RFC1751.nix
