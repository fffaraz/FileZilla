AUTOMAKE_OPTIONS = subdir-objects

noinst_LIBRARIES = libfzputtycommon.a

libfzputtycommon_a_SOURCES = \
			conf.c \
			console.c \
			ecc.c \
			import.c \
			marshal.c \
			memory.c \
			misc.c \
			mpint.c \
			rfc6979.c \
			sshaes.c \
			sshargon2.c \
			sshauxcrypt.c \
			sshbcrypt.c \
			sshblake2.c \
			sshblowf.c \
			sshdes.c \
			sshdss.c \
			sshecc.c \
			sshhmac.c \
			sshmd5.c \
			sshprng.c \
			sshpubk.c \
			sshrand.c \
			sshrsa.c \
			sshsha.c \
			sshsh256.c \
			sshsh512.c \
			sshsha.c \
			sshsha3.c \
			stripctrl.c \
			tree234.c \
			utils.c \
			fzprintf.c \
			wcwidth.c

if FZ_WINDOWS
libfzputtycommon_a_SOURCES += \
			windows/wincons.c \
			windows/winmisc.c \
			windows/winmiscs.c \
			windows/winnohlp.c \
			windows/winnoise.c \
			windows/winnojmp.c \
			windows/winstore.c
else
libfzputtycommon_a_SOURCES += \
			unix/uxcons.c \
			unix/uxmisc.c \
			unix/uxnoise.c \
			unix/uxpoll.c \
			unix/uxstore.c \
			unix/uxutils.c
endif

bin_PROGRAMS = fzsftp fzputtygen

fzsftp_SOURCES = \
		be_misc.c \
		be_ssh.c \
		callback.c \
		clicons.c \
		cmdline.c \
		cproxy.c \
		errsock.c \
		fzsftp.c \
		logging.c \
		mainchan.c \
		noshare.c \
		nullplug.c \
		portfwd.c \
		psftp.c \
		proxy.c \
		pproxy.c \
		pinger.c \
		settings.c \
		sftp.c \
		sftpcommon.c \
		ssh.c \
		ssh2bpp.c \
		ssh2censor.c \
		ssh2connection.c \
		ssh2connection-client.c \
		ssh2kex-client.c \
		ssh2transhk.c \
		ssh2transport.c \
		ssh2userauth.c \
		ssharcf.c \
		sshccp.c \
		sshcommon.c \
		sshcrc.c \
		sshcrcda.c \
		sshdes.c \
		sshdh.c \
		sshdss.c \
		sshmac.c \
		sshshare.c \
		sshutils.c \
		sshverstring.c \
		sshzlib.c \
		timing.c \
		version.c \
		wildcard.c \
		x11fwd.c

if FZ_WINDOWS
fzsftp_SOURCES += \
		windows/wincapi.c \
		windows/wincliloop.c \
		windows/windefs.c \
		windows/winhandl.c \
		windows/winhsock.c \
		windows/winnet.c \
		windows/winnohlp.c \
		windows/winnojmp.c \
		windows/winnpc.c \
		windows/winnps.c \
		windows/winpgntc.c \
		windows/winsecur.c \
		windows/winselcli.c \
		windows/winsftp.c \
		windows/wintime.c
else
fzsftp_SOURCES += \
		time.c \
		unix/uxagentc.c \
		unix/uxcliloop.c \
		unix/uxnet.c \
		unix/uxnoise.c \
		unix/uxpeer.c \
		unix/uxsel.c \
		unix/uxsftp.c
endif

fzputtygen_SOURCES = cmdgen.c \
		     notiming.c \
		     version.c


noinst_HEADERS = \
	charset.h \
	defs.h \
	ecc.h \
	fzprintf.h \
	fzsftp.h \
	marshal.h \
	misc.h \
	mpint.h \
	mpint_i.h \
	network.h \
	pageant.h \
	proxy.h \
	psftp.h \
	putty.h \
	puttymem.h \
	puttyps.h \
	sftp.h \
	ssh.h \
	ssh2connection.h \
	ssh2transport.h \
	sshblowf.h \
	sshbpp.h \
	sshchan.h \
	sshcr.h \
	sshgssc.h \
	sshkeygen.h \
	sshppl.h \
	sshserver.h \
	sshsignals.h \
	sshttymodes.h \
	storage.h \
	terminal.h \
	tree234.h \
	unix/unix.h \
	unix/uxutils.h \
	windows/wincapi.h \
	windows/winsecur.h \
	windows/winstuff.h \
	windows/rcstuff.h

dist_noinst_DATA = \
	windows/psftp.rc \
	windows/version.rc2 \
	windows/pscp.ico \
	windows/windows_manifest.xml

if USE_RESOURCEFILE
  nodist_noinst_DATA = windows/psftp.o

  windows/psftp.o: $(srcdir)/windows/psftp.rc $(srcdir)/windows/windows_manifest.xml
	@if [ -f $@~ ]; then rm $@~; fi
	@WINDRES@ --include-dir=$(srcdir)/windows $(WINDRESFLAGS) -D GNU_WINDRES $(srcdir)/windows/psftp.rc $@~
	@if [ -f $@ ]; then rm $@; fi
	mv $@~ $@

  RESOURCEFILE = windows/psftp.o
endif

AM_CPPFLAGS = -I$(srcdir) -I$(top_builddir)/config

fzsftp_LDADD = libfzputtycommon.a
fzsftp_LDADD += $(NETTLE_LIBS)


if FZ_WINDOWS
  COMMON_CPPFLAGS = $(AM_CPPFLAGS) -D_ISOC99_SOURCE -DNO_GSSAPI \
		 -D_WINDOWS -DSECURITY_WIN32 $(NETTLE_CFLAGS)

  libfzputtycommon_a_CPPFLAGS = $(COMMON_CPPFLAGS)

  fzsftp_CPPFLAGS = $(COMMON_CPPFLAGS)
  fzsftp_LDADD += $(RESOURCEFILE)
  fzsftp_LDADD += -lws2_32 -lole32

  fzputtygen_CPPFLAGS = $(COMMON_CPPFLAGS)
  fzputtygen_LDADD = libfzputtycommon.a $(RESOURCEFILE) $(NETTLE_LIBS)
  fzputtygen_LDADD += -lole32
else
  libfzputtycommon_a_CPPFLAGS = $(AM_CPPFLAGS) -DNO_GSSAPI -D_FILE_OFFSET_BITS=64

  fzsftp_CPPFLAGS = $(AM_CPPFLAGS) -D_FILE_OFFSET_BITS=64 -DNO_GSSAPI

  fzputtygen_CPPFLAGS = $(AM_CPPFLAGS) -DNO_GSSAPI
  fzputtygen_LDADD = libfzputtycommon.a $(NETTLE_LIBS)
endif

libfzputtycommon_a_CPPFLAGS += $(NETTLE_CFLAGS)
fzsftp_CPPFLAGS += $(NETTLE_CFLAGS)
fzputtygen_CPPFLAGS += $(NETTLE_CFLAGS)

if MACAPPBUNDLE
noinst_DATA = $(top_builddir)/FileZilla.app/Contents/MacOS/fzsftp$(EXEEXT)
endif

$(top_builddir)/FileZilla.app/Contents/MacOS/fzsftp$(EXEEXT): fzsftp fzputtygen
	mkdir -p $(top_builddir)/FileZilla.app/Contents/MacOS
	cp -f fzsftp $(top_builddir)/FileZilla.app/Contents/MacOS/fzsftp
	cp -f fzputtygen $(top_builddir)/FileZilla.app/Contents/MacOS/fzputtygen
