FROM fedora:latest
RUN dnf install -y appstream curl file make automake libtool gcc gcc-c++ boost-devel gmp-devel nettle-devel gnutls-devel gettext-devel wxGTK-devel pugixml-devel xdg-utils sqlite-devel

RUN \
	cd /opt && \
	curl -L -o ./appimagetool-x86_64.AppImage https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage && \
	chmod +x ./appimagetool-x86_64.AppImage && \
	exit 0

ADD ./libfilezilla /opt/libfilezilla
RUN \
	cd /opt/libfilezilla && \
	autoreconf -f -i && \
	./configure && \
	make -j$(nproc) && \
	make install && \
	exit 0

ADD ./filezilla /opt/filezilla
RUN \
	cd /opt/filezilla && \
	PKG_CONFIG_PATH=/usr/local/lib/pkgconfig ./configure && \
	make -j$(nproc) && \
	make install && \
	exit 0

ADD ./AppRun.sh /opt/approot/AppRun
ADD ./filezilla.desktop /opt/approot
RUN \
	mkdir -p /opt/approot/opt/filezilla && \
	cp /opt/filezilla/src/interface/resources/480x480/filezilla.png /opt/approot/opt/filezilla/icon.png && \
	cp -P /usr/local/lib/libf* /opt/approot/opt/filezilla && \
	cp /usr/local/bin/filezilla /opt/approot/opt/filezilla && \
	chmod +x /opt/approot/AppRun && \
	exit 0

ENTRYPOINT ["/opt/appimagetool-x86_64.AppImage", "/opt/approot", "/opt/FileZilla.AppImage"]
