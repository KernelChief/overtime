#!/usr/bin/env bash
# Overtime hour bank. Run this on the Proxmox host:
#
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/KernelChief/overtime/main/ct/overtime.sh)"
#
# Existing container instead of a new one: ADOPT=1 CTID=<id> bash -c "..."
# More options (storage, static IP, auto-update, ...) are listed at the top of misc/build.func.

GIT_HOST="${GIT_HOST:-https://github.com}"
GIT_USER="${GIT_USER:-KernelChief}"
APP="overtime"
APP_TITLE="Overtime hour bank"
APP_BRANCH="${APP_BRANCH:-main}"
SCRIPTS_BRANCH="${SCRIPTS_BRANCH:-main}"
APP_REPO="$GIT_HOST/$GIT_USER/overtime"  # cloned by install.func; a plain https git remote either way
case "$GIT_HOST" in
  https://github.com*) SCRIPTS_REPO="https://raw.githubusercontent.com/$GIT_USER/overtime/$SCRIPTS_BRANCH" ;;
  *) SCRIPTS_REPO="$GIT_HOST/$GIT_USER/overtime/raw/branch/$SCRIPTS_BRANCH" ;;  # Gitea-style raw-file layout, for a self-hosted git forge
esac
PORT=8080
CORES="${CORES:-1}"
RAM="${RAM:-256}"
DISK="${DISK:-3}"

CURL=(curl -fsSL)

BUILD="$("${CURL[@]}" "$SCRIPTS_REPO/misc/build.func")" \
  || { echo "Couldn't fetch misc/build.func from $SCRIPTS_REPO." >&2; exit 1; }
eval "$BUILD"
build_container
