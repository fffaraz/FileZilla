#!/bin/bash
# Entry point script for AppImage

SELF=$(readlink -f "$0")
HERE=${SELF%/*}

unset LD_LIBRARY_PATH LD_PRELOAD LD_AUDIT GTK_PATH GIO_MODULE_DIR GCONV_PATH LOCPATH
unset $(env | awk -F= '/^SNAP/ {print $1}')

export LD_LIBRARY_PATH="${HERE}/opt/filezilla:/usr/lib"
export FZ_DATADIR="${HERE}/opt/filezilla/share"
export FZ_FZSFTP="${HERE}/opt/filezilla/fzsftp"
export FZ_FZPUTTYGEN="${HERE}/opt/filezilla/fzputtygen"

# ldd "${HERE}/opt/filezilla/filezilla"

exec "${HERE}/opt/filezilla/filezilla" "$@"
