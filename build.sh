#!/bin/bash
set -exuo pipefail

rm -f ./FileZilla.AppImage
docker rm -f filezilla

if [ "${1:-}" = "--fedora" ]; then
	DOCKERFILE=Dockerfile.fedora
elif [ "${1:-}" = "--ubuntu" ]; then
	DOCKERFILE=Dockerfile.ubuntu
elif [ -f /etc/fedora-release ]; then
	DOCKERFILE=Dockerfile.fedora
else
	DOCKERFILE=Dockerfile.ubuntu
fi

docker build -f "docker/$DOCKERFILE" -t filezilla .

# -it only when attached to a terminal, so this also works in CI
RUN_FLAGS=(--privileged)
if [ -t 0 ] && [ -t 1 ]; then
	RUN_FLAGS+=(-it)
fi

docker run "${RUN_FLAGS[@]}" --name filezilla filezilla
docker cp filezilla:/opt/FileZilla.AppImage $(pwd)/FileZilla.AppImage
docker rm -f filezilla

# debug:
# docker run --privileged -it --entrypoint /bin/bash filezilla
# cd /opt && ./appimagetool-x86_64.AppImage ./approot ./FileZilla.AppImage
