{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  packages = with pkgs; [
    python312
    poetry
    ruff
  ];

  shellHook = ''
  if [[ -d .venv/ ]]; then
    source .venv/bin/activate
  fi
  '';
}