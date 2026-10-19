#!/usr/bin/env bash
# Runs inside the container (pushed there by ct/overtime.sh).
EXTRA_PACKAGES=""   # extra dnf packages this app needs, if any
# shellcheck disable=SC1091
. /root/install.func
install_app
