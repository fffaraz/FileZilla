#!/bin/bash
set -exuo pipefail

rm -f ./FileZilla.AppImage
docker rm -f filezilla

docker build -t filezilla .
docker run --privileged -it --name filezilla filezilla
docker cp filezilla:/opt/FileZilla.AppImage $(pwd)/FileZilla.AppImage
docker rm -f filezilla

# docker run --privileged -it --entrypoint /bin/bash filezilla
# cd /opt && ./appimagetool-x86_64.AppImage ./approot ./FileZilla.AppImage

# source code:
# https://filezilla-project.org/download.php?show_all=1
# https://lib.filezilla-project.org/download.php
