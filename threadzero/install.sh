#!/usr/bin/env bash
# THREADZERO installer for Linux / macOS / WSL.  Usage: ./install.sh [--no-web]
set -euo pipefail
cd "$(dirname "$0")"

need() { command -v "$1" >/dev/null 2>&1 || { echo "✘ missing: $1 — $2"; MISSING=1; }; }
MISSING=0
need python3 "install Python >= 3.10 (https://www.python.org/downloads/ or your package manager)"
need ghc "install GHC >= 9.4:  curl --proto '=https' --tlsv1.2 -sSf https://get-ghcup.haskell.org | sh   (or: sudo apt install ghc)"
[[ "${1:-}" == "--no-web" ]] || need npm "install Node.js >= 18 (https://nodejs.org) to build the web studio, or pass --no-web"
[[ $MISSING -eq 0 ]] || exit 1

echo "▶ Python dependencies"
python3 -m pip install -r requirements.txt
python3 -m pip install -e .

echo "▶ Haskell core"
mkdir -p haskell/build
ghc -O1 -ihaskell/src -ihaskell/app -outputdir haskell/build -o haskell/build/threadzero-core haskell/app/Main.hs

if [[ "${1:-}" != "--no-web" ]]; then
  echo "▶ Web studio"
  (cd web && npm install && npm run build)
fi

echo "▶ Verifying"
python3 -m threadzero doctor
echo
echo "✔ Done.  Start the studio:  threadzero serve     (then open http://127.0.0.1:8737)"
