lib_LTLIBRARIES = libfilezilla.la

libfilezilla_la_SOURCES = \
	aio/aio.cpp \
	aio/reader.cpp \
	aio/writer.cpp \
	aio/xml_writer.cpp \
	ascii_layer.cpp \
	buffer.cpp \
	encode.cpp \
	encryption.cpp \
	event.cpp \
	event_handler.cpp \
	event_loop.cpp \
	file.cpp \
	hash.cpp \
	http/client.cpp \
	http/client_request.cpp \
	http/client_response.cpp \
	http/digest.cpp \
	http/headers.cpp \
	http/throttler.cpp \
	hostname_lookup.cpp \
	impersonation.cpp \
	invoker.cpp \
	iputils.cpp \
	json.cpp \
	jws.cpp \
	local_filesys.cpp \
	logger.cpp \
	mutex.cpp \
	nonowning_buffer.cpp \
	process.cpp \
	rate_limiter.cpp \
	rate_limited_layer.cpp \
	recursive_remove.cpp \
	signature.cpp \
	socket.cpp \
	socket_errors.cpp \
	string.cpp \
	thread.cpp \
	thread_pool.cpp \
	tls_info.cpp \
	tls_layer.cpp \
	tls_layer_impl.cpp \
	tls_params.cpp \
	tls_system_trust_store.cpp \
	time.cpp \
	translate.cpp \
	uri.cpp \
	util.cpp \
	version.cpp \
	xml.cpp

nobase_include_HEADERS = \
	libfilezilla/basic_tls_params.hpp \
	libfilezilla/aio/aio.hpp \
	libfilezilla/aio/reader.hpp \
	libfilezilla/aio/writer.hpp \
	libfilezilla/aio/xml_writer.hpp \
	libfilezilla/ascii_layer.hpp \
	libfilezilla/apply.hpp \
	libfilezilla/buffer.hpp \
	libfilezilla/encode.hpp \
	libfilezilla/encryption.hpp \
	libfilezilla/event.hpp \
	libfilezilla/event_handler.hpp \
	libfilezilla/event_loop.hpp \
	libfilezilla/file.hpp \
	libfilezilla/format.hpp \
	libfilezilla/forward_like.hpp \
	libfilezilla/fsresult.hpp \
	libfilezilla/hash.hpp \
	libfilezilla/http/client.hpp \
	libfilezilla/http/client_request.hpp \
	libfilezilla/http/client_response.hpp \
	libfilezilla/http/digest.hpp \
	libfilezilla/http/headers.hpp \
	libfilezilla/hostname_lookup.hpp \
	libfilezilla/impersonation.hpp \
	libfilezilla/invoker.hpp \
	libfilezilla/iputils.hpp \
	libfilezilla/json.hpp \
	libfilezilla/jws.hpp \
	libfilezilla/libfilezilla.hpp \
	libfilezilla/local_filesys.hpp \
	libfilezilla/logger.hpp \
	libfilezilla/mutex.hpp \
	libfilezilla/nonowning_buffer.hpp \
	libfilezilla/optional.hpp \
	libfilezilla/process.hpp \
	libfilezilla/rate_limiter.hpp \
	libfilezilla/rate_limited_layer.hpp \
	libfilezilla/recursive_remove.hpp \
	libfilezilla/rwmutex.hpp \
	libfilezilla/shared.hpp \
	libfilezilla/signature.hpp \
	libfilezilla/socket.hpp \
	libfilezilla/string.hpp \
	libfilezilla/thread.hpp \
	libfilezilla/thread_pool.hpp \
	libfilezilla/time.hpp \
	libfilezilla/tls_info.hpp \
	libfilezilla/tls_layer.hpp \
	libfilezilla/tls_params.hpp \
	libfilezilla/tls_system_trust_store.hpp \
	libfilezilla/translate.hpp \
	libfilezilla/uri.hpp \
	libfilezilla/util.hpp \
	libfilezilla/visibility_helper.hpp \
	libfilezilla/xml.hpp \
	libfilezilla/private/defs.hpp \
	libfilezilla/private/visibility.hpp \
	libfilezilla/glue/wx.hpp \
	libfilezilla/glue/wxinvoker.hpp

nobase_nodist_include_HEADERS = \
	libfilezilla/version.hpp

libfilezilla_la_LDFLAGS = $(AM_LDFLAGS)
libfilezilla_la_LIBADD = $(libdeps)

dist_noinst_HEADERS = \
	http/throttler.hpp \
	tls_layer_impl.hpp \
	tls_system_trust_store_impl.hpp \
	windows/poller.hpp \
	windows/security_descriptor_builder.hpp \
	unix/poller.hpp

if FZ_WINDOWS

libfilezilla_la_SOURCES += \
	windows/dll.cpp \
	windows/poller.cpp \
	windows/registry.cpp \
	windows/security_descriptor_builder.cpp

nobase_include_HEADERS += \
	libfilezilla/glue/registry.hpp \
	libfilezilla/glue/windows.hpp \
	libfilezilla/glue/dll.hpp

windows/libfilezilla_rc.o: $(srcdir)/windows/libfilezilla.rc $(srcdir)/windows/manifest.xml windows/version.rc
	@if [ -f $@~ ]; then rm $@~; fi
	@WINDRES@ --include-dir=windows --include-dir=$(srcdir)/windows $(WINDRESFLAGS) $(srcdir)/windows/libfilezilla.rc -D GNU_WINDRES -D HAS_VERSIONRC $@~ || rm $@~
	@if [ -f $@ ]; then rm $@; fi
	mv $@~ $@
EXTRA_libfilezilla_la_DEPENDENCIES = windows/libfilezilla_rc.o
libfilezilla_la_LDFLAGS += -Wl,windows/libfilezilla_rc.o

else

libfilezilla_la_SOURCES += \
	glue/unix.cpp \
	unix/poller.cpp

nobase_include_HEADERS += \
	libfilezilla/glue/unix.hpp

endif

if FZ_MAC
libfilezilla_la_LDFLAGS += -framework CoreServices
endif

if FZ_UNIX
libfilezilla_la_LDFLAGS += -lcrypt
endif

libfilezilla_la_CPPFLAGS = $(AM_CPPFLAGS)
libfilezilla_la_CPPFLAGS += -I$(top_builddir)/config
libfilezilla_la_CPPFLAGS += -DBUILDING_LIBFILEZILLA
libfilezilla_la_CPPFLAGS += $(GMP_CFLAGS) $(NETTLE_CFLAGS) $(GNUTLS_CFLAGS)

# Needed for version.hpp in out-of-tree builds
libfilezilla_la_CPPFLAGS += -I. -I$(srcdir)/libfilezilla

libfilezilla_la_CXXFLAGS = $(AM_CXXFLAGS)
libfilezilla_la_CXXFLAGS += -fvisibility=hidden

libfilezilla_la_LDFLAGS += -no-undefined
libfilezilla_la_LDFLAGS += -version-info $(LIBRARY_VERSION)

libfilezilla_la_LIBADD += $(GNUTLS_LIBS) $(NETTLE_LIBS) $(HOGWEED_LIBS) $(GMP_LIBS)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libfilezilla.pc

DISTCLEANFILES = libfilezilla.pc windows/version.rc
CLEANFILES = windows/libfilezilla_rc.o

dist_noinst_DATA = windows/libfilezilla.rc windows/manifest.xml
