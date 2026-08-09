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

# Install a desktop entry and icons into the user's home directory.
#
# Wayland compositors resolve a window's icon in their own process, by matching
# the window's app_id ("filezilla") against a .desktop file in XDG_DATA_DIRS.
# The copies bundled inside the AppImage are invisible to them, so without this
# the window falls back to a generic icon. Set FZ_NO_DESKTOP_INTEGRATION=1 to
# skip it and leave the host untouched.
integrate() {
	# $APPIMAGE is only set when running from the AppImage runtime.
	[ -n "${APPIMAGE:-}" ] || return 0
	[ -z "${FZ_NO_DESKTOP_INTEGRATION:-}" ] || return 0
	[ -n "${HOME:-}" ] && [ -w "${HOME}" ] || return 0

	local data_home=${XDG_DATA_HOME:-$HOME/.local/share}
	local apps=${data_home}/applications
	local icons=${data_home}/icons/hicolor
	local target=${apps}/filezilla.desktop
	local exec_line="Exec=\"${APPIMAGE}\""
	local source=${HERE}/usr/share/applications/filezilla.desktop

	[ -f "${source}" ] || return 0

	# Already installed for this exact path; nothing to do. Re-runs if the
	# AppImage has since been moved or renamed.
	if [ -f "${target}" ] && grep -qxF "${exec_line}" "${target}"; then
		return 0
	fi

	mkdir -p "${apps}" || return 0

	local dir size
	for dir in "${HERE}"/usr/share/icons/hicolor/*/apps; do
		[ -d "${dir}" ] || continue
		size=${dir%/apps}
		size=${size##*/}
		mkdir -p "${icons}/${size}/apps" &&
			cp -f "${dir}"/filezilla.* "${icons}/${size}/apps/" 2>/dev/null
	done

	# Point Exec at wherever the AppImage actually lives, and pin the app_id
	# match so the compositor ties the running window to this entry.
	awk -v exec_line="${exec_line}" '
		/^Exec=/ { print exec_line; next }
		/^TryExec=/ { next }
		/^StartupWMClass=/ { seen = 1 }
		{ print }
		END { if (!seen) print "StartupWMClass=filezilla" }
	' "${source}" > "${target}.tmp" 2>/dev/null &&
		mv -f "${target}.tmp" "${target}" ||
		{ rm -f "${target}.tmp"; return 0; }

	if command -v gtk-update-icon-cache >/dev/null 2>&1; then
		gtk-update-icon-cache -f -t --ignore-theme-index "${icons}" >/dev/null 2>&1
	fi
	if command -v update-desktop-database >/dev/null 2>&1; then
		update-desktop-database "${apps}" >/dev/null 2>&1
	fi

	return 0
}

integrate

# ldd "${HERE}/opt/filezilla/filezilla"

exec "${HERE}/opt/filezilla/filezilla" "$@"
