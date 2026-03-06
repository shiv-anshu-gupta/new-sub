#!/bin/bash
# Launch SV Subscriber with snap environment variables cleaned out.
# VS Code snap pollutes GTK_PATH / GTK_EXE_PREFIX / LOCPATH etc.,
# which causes Tauri's WebKitGTK to load snap's old glibc 2.31 libpthread
# instead of the system's newer glibc — resulting in:
#   "symbol lookup error: libpthread.so.0: undefined symbol: __libc_pthread_init"
#
# This script unsets those snap-injected variables before launching.

cd "$(dirname "$0")/src-tauri" || exit 1

export PATH="$HOME/.cargo/bin:$PATH"

# Remove snap VS Code's GTK/glib overrides
unset GTK_PATH
unset GTK_EXE_PREFIX
unset GTK_IM_MODULE_FILE
unset LOCPATH
unset GIO_MODULE_DIR
unset GSETTINGS_SCHEMA_DIR

# Restore XDG dirs to system defaults (snap overrides these)
export XDG_DATA_HOME="$HOME/.local/share"
export XDG_DATA_DIRS="/usr/share/ubuntu:/usr/share/gnome:/usr/local/share:/usr/share:/var/lib/snapd/desktop"

echo "[run.sh] Starting SV Subscriber (snap env cleaned)..."
exec cargo run "$@"
