#!/bin/bash
# Entry point script for AppImage

SELF=$(readlink -f "$0")
HERE=${SELF%/*}
EXEC="${HERE}/opt/filezilla/filezilla"

export LD_LIBRARY_PATH="/usr/lib:${HERE}/opt/filezilla"

exec "${EXEC}"
