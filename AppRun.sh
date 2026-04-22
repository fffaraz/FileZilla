#!/bin/bash
# Entry point script for AppImage

SELF=$(readlink -f "$0")
HERE=${SELF%/*}

export LD_LIBRARY_PATH="${HERE}/opt/filezilla:/usr/lib"
export FZ_DATADIR="${HERE}/opt/filezilla/share"
export FZ_FZSFTP="${HERE}/opt/filezilla/fzsftp"
export FZ_FZPUTTYGEN="${HERE}/opt/filezilla/fzputtygen"

exec "${HERE}/opt/filezilla/filezilla" "$@"
