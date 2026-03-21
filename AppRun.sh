#!/bin/bash
# Entry point script for AppImage

SELF=$(readlink -f "$0")
HERE=${SELF%/*}
EXEC="${HERE}/opt/filezilla/filezilla"

export LD_LIBRARY_PATH="/usr/lib:${HERE}/opt/filezilla"
export FZ_DATADIR="${HERE}/opt/filezilla/share"
export FZ_FZSFTP="${HERE}/opt/filezilla/fzsftp"
export FZ_FZPUTTYGEN="${HERE}/opt/filezilla/fzputtygen"

exec "${EXEC}"
