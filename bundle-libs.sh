#!/bin/sh
# Copy the shared libraries an executable needs into the AppDir.
#
# Usage: bundle-libs.sh <dest-dir> <binary> [binary...]
#
# ldd reports the full transitive closure, so every dependency is covered by
# walking the main binary alone. What it cannot know is which of those should
# actually travel with the application: anything on the exclude list below has
# to come from the host instead, because a bundled copy either desynchronises
# from host-side data (GTK theme engines, gdk-pixbuf loaders, fontconfig
# caches) or has to match kernel/driver state it cannot see (Mesa, libdrm,
# display servers). Everything else is bundled, which is the side that matters
# for portability - the host may have the wrong version of wxWidgets, or no
# libargon2 at all.
set -eu

dest=$1
shift

excluded() {
	case $1 in
	# Loader, C library and compiler runtime.
	ld-linux*|libc.so.*|libm.so.*|libdl.so.*|libpthread.so.*|librt.so.*|\
	libresolv.so.*|libnsl.so.*|libutil.so.*|libanl.so.*|libmvec.so.*|\
	libgcc_s.so.*|libstdc++.so.*)
		return 0 ;;
	# Graphics drivers and display servers - must match the host's.
	libGL*.so.*|libEGL*.so.*|libOpenGL.so.*|libGLdispatch.so.*|\
	libglapi.so.*|libdrm.so.*|libgbm.so.*|libepoxy.so.*|\
	libX*.so.*|libxcb*.so.*|libxkbcommon*.so.*|libwayland-*.so.*|\
	libICE.so.*|libSM.so.*)
		return 0 ;;
	# GLib/GTK desktop stack - loads modules, themes and image loaders from
	# host paths, so a bundled copy drifts out of sync with them.
	libglib-2.0.so.*|libgobject-2.0.so.*|libgio-2.0.so.*|\
	libgmodule-2.0.so.*|libgthread-2.0.so.*|libgtk-3.so.*|libgdk-3.so.*|\
	libgdk_pixbuf-2.0.so.*|libatk-*.so.*|libatspi.so.*|libcairo*.so.*|\
	libpango*.so.*|libharfbuzz*.so.*|libfribidi.so.*|libthai.so.*|\
	libdatrie.so.*|libgraphite2.so.*|libpixman-1.so.*|libfontconfig.so.*|\
	libfreetype.so.*|libcloudproviders.so.*|libjson-glib-*.so.*|\
	libglycin-*.so.*|libtinysparql-*.so.*)
		return 0 ;;
	# System services and ubiquitous base libraries. AppRun puts the bundle
	# directory on LD_LIBRARY_PATH, which host libraries loaded into the
	# process also search - so anything the host stack itself pulls in has to
	# be left alone, or the host's fontconfig and systemd end up bound to our
	# copy of it. These are all ABI-stable and present everywhere anyway.
	libdbus-1.so.*|libsystemd.so.*|libudev.so.*|libselinux.so.*|\
	libseccomp.so.*|libblkid.so.*|libmount.so.*|libcap.so.*|libz.so.*|\
	liblzma.so.*|libbz2.so.*|libbrotli*.so.*|libffi.so.*|libpcre2-8.so.*|\
	libxml2.so.*|libpng16.so.*|liblcms2.so.*|libexpat.so.*|libuuid.so.*|\
	libzstd.so.*)
		return 0 ;;
	esac
	return 1
}

mkdir -p "$dest"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# soname -> path, from ldd's full transitive closure. Used purely to resolve
# names; which of them get bundled is decided by the walk below.
for bin in "$@"; do
	if ! ldd "$bin" >/dev/null 2>&1; then
		echo "bundle-libs: not a dynamic executable: $bin" >&2
		exit 1
	fi
	# "soname => /path/to/soname (0xaddr)" is the only form carrying a
	# resolved dependency; the vdso and the loader itself have no => field.
	# An unresolved one reads "soname => not found".
	ldd "$bin" | awk '$2 == "=>" { print $1, $3 }' >> "$work/map"
done

if grep -q ' not$' "$work/map"; then
	echo "bundle-libs: unresolved dependencies:" >&2
	awk '$2 == "not" { print "  " $1 }' "$work/map" | sort -u >&2
	exit 1
fi

# Direct DT_NEEDED entries of one file.
needed() {
	objdump -p "$1" 2>/dev/null | awk '$1 == "NEEDED" { print $2 }'
}

# Walk the dependency graph from the binaries outwards, stopping at excluded
# libraries rather than stepping through them. Taking ldd's flat closure
# instead would bundle whatever the host stack drags in behind it - libgcrypt
# and liblz4 arrive only via libsystemd, and belong to the host copy of it.
for bin in "$@"; do
	needed "$bin" >> "$work/queue"
done
: > "$work/seen"

bundled=0
while [ -s "$work/queue" ]; do
	soname=$(head -n 1 "$work/queue")
	sed -i 1d "$work/queue"

	grep -qxF "$soname" "$work/seen" && continue
	echo "$soname" >> "$work/seen"

	excluded "$soname" && continue

	path=$(awk -v s="$soname" '$1 == s { print $2; exit }' "$work/map")
	if [ -z "$path" ]; then
		echo "bundle-libs: cannot resolve $soname" >&2
		exit 1
	fi

	# Copy under the soname the loader will ask for, dereferencing the usual
	# libfoo.so -> libfoo.so.1 -> libfoo.so.1.2.3 chain so that a single
	# regular file answers the lookup.
	cp -Lf "$path" "$dest/$soname"
	bundled=$((bundled + 1))

	needed "$path" >> "$work/queue"
done

echo "bundle-libs: bundled $bundled shared libraries into $dest"
