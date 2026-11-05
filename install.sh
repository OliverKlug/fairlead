#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2026 Oliver Klug
# SPDX-License-Identifier: Apache-2.0
# Install the fairlead CLI for this machine. Not a public curl installer.
# The wrapper points FAIRLEAD_ROOT at this repo's pack/ directory.
# Re-run after the pack or the binary moves.
set -eu

APP=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DOCS="$APP/pack"
if [ ! -f "$DOCS/tests/doctor/cases.json" ]; then
  echo "pack not found: $DOCS/tests/doctor/cases.json" >&2
  exit 1
fi

cargo build --release -p fairlead-cli --manifest-path "$APP/Cargo.toml"

lib="$HOME/.local/lib/fairlead"
bin="$HOME/.local/bin"
mkdir -p "$lib" "$bin"
cp -f "$APP/target/release/fairlead" "$lib/fairlead"
chmod 755 "$lib/fairlead"

cat > "$bin/fairlead" <<EOF
#!/bin/sh
export FAIRLEAD_ROOT="$DOCS"
exec "$lib/fairlead" "\$@"
EOF
chmod 755 "$bin/fairlead"

echo "installed: $bin/fairlead"
echo "pack: $DOCS"
case ":${PATH}:" in
  *":$bin:"*) ;;
  *) echo "PATH is missing $bin" ;;
esac
echo "next: fairlead install-hooks /path/to/a-disposable-repo"
echo "do not run install-hooks in this repository"
