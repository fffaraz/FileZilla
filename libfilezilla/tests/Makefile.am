# Rules for the test code (use `make check` to execute)

TESTS = test ratelimit_test
check_PROGRAMS = $(TESTS)

test_SOURCES =  test.cpp \
		buffer.cpp \
		crypto.cpp \
		dispatch.cpp \
		eventloop.cpp \
		format.cpp \
		hash.cpp \
		invoker.cpp \
		iputils.cpp \
		json.cpp \
		smart_pointer.cpp \
		socket.cpp \
		string.cpp \
		time.cpp \
		util.cpp \
		xml.cpp

test_CPPFLAGS = $(AM_CPPFLAGS)
test_CPPFLAGS += $(CPPUNIT_CFLAGS)

test_LDFLAGS = $(AM_LDFLAGS)
test_LDFLAGS += -no-install

test_LDADD = ../lib/libfilezilla.la
test_LDADD += $(CPPUNIT_LIBS)
test_LDADD += $(libdeps)

AM_TESTS_ENVIRONMENT = GNUTLS_SYSTEM_PRIORITY_FILE=/dev/null

test_DEPENDENCIES = ../lib/libfilezilla.la

noinst_HEADERS = test_utils.hpp


ratelimit_test_SOURCES = \
	ratelimit.cpp

ratelimit_test_CPPFLAGS = $(AM_CPPFLAGS)
ratelimit_test_LDFLAGS = $(AM_LDFLAGS) -no-install
ratelimit_test_LDADD = ../lib/libfilezilla.la $(libdeps)
ratelimit_test_DEPENDENCIES = ../lib/libfilezilla.la
